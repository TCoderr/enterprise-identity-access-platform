using System.Collections.Immutable;
using System.Security.Claims;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Iam.Protocol;

public enum GrantValidity
{
    Valid,
    Unknown,
    GrantRevoked,
    SessionEnded,
    UserDisabled,
    ClientDisabled,
}

public sealed record GrantState(GrantValidity Validity, Guid SessionId, Guid UserId, Guid ApplicationId, DateTimeOffset AuthTime, string Amr)
{
    public bool IsValid => Validity == GrantValidity.Valid;
}

/// <summary>
/// Grants connect tokens to their central session. Every token operation (code exchange, refresh, introspection,
/// userinfo) asks this service for the current state in the database instead of trusting the token alone.
/// </summary>
public sealed class GrantService(
    IamDbContext db,
    IOpenIddictAuthorizationManager authorizations,
    AuditWriter audit,
    TimeProvider time,
    IOptions<CentralSessionOptions> sessionOptions)
{
    /// <summary>
    /// Creates the grant for one successful authorization request: an OpenIddict authorization entry plus its link
    /// to the session, in the caller's transaction. Returns the authorization identifier to attach to the tokens.
    /// </summary>
    public async Task<string> CreateAsync(
        ClaimsIdentity identity,
        CurrentSession session,
        Guid applicationId,
        string clientId,
        ImmutableArray<string> scopes,
        CancellationToken cancellationToken)
    {
        var authorization = await authorizations.CreateAsync(
            identity: identity,
            subject: session.UserId.ToString(),
            client: applicationId.ToString(),
            type: AuthorizationTypes.AdHoc,
            scopes: scopes,
            cancellationToken: cancellationToken);
        var id = await authorizations.GetIdAsync(authorization, cancellationToken)
                 ?? throw new InvalidOperationException("The authorization entry has no identifier.");

        db.SessionGrants.Add(new SessionGrant
        {
            AuthorizationId = Guid.Parse(id),
            SessionId = session.Id,
            UserId = session.UserId,
            ApplicationId = applicationId,
            ClientId = clientId,
            Scopes = string.Join(' ', scopes),
            CreatedAt = time.GetUtcNow(),
        });
        audit.Add("grant.created", AuditOutcome.Success, AuditActor.User, session.UserId.ToString(), "grant", id, $"client={clientId}");
        await db.SaveChangesAsync(cancellationToken);
        return id;
    }

    /// <summary>Current validity of a grant: the grant itself, its session, its user and its client.</summary>
    public async Task<GrantState> InspectAsync(string? authorizationId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(authorizationId, out var id))
        {
            return new GrantState(GrantValidity.Unknown, default, default, default, default, string.Empty);
        }

        var row = await (
            from grant in db.SessionGrants.AsNoTracking()
            join session in db.UserSessions.AsNoTracking() on grant.SessionId equals session.Id
            join user in db.Users.AsNoTracking() on grant.UserId equals user.Id
            join settings in db.ClientSettings.AsNoTracking() on grant.ApplicationId equals settings.ApplicationId
            where grant.AuthorizationId == id
            select new
            {
                grant.RevokedAt,
                grant.SessionId,
                grant.UserId,
                grant.ApplicationId,
                SessionRevokedAt = session.RevokedAt,
                session.AbsoluteExpiresAt,
                session.LastSeenAt,
                session.AuthTime,
                session.Amr,
                user.IsDisabled,
                ClientDisabled = settings.IsDisabled,
            }).SingleOrDefaultAsync(cancellationToken);
        if (row is null)
        {
            return new GrantState(GrantValidity.Unknown, default, default, default, default, string.Empty);
        }

        var now = time.GetUtcNow();
        var validity = row switch
        {
            { RevokedAt: not null } => GrantValidity.GrantRevoked,
            { SessionRevokedAt: not null } => GrantValidity.SessionEnded,
            _ when now >= row.AbsoluteExpiresAt || now - row.LastSeenAt >= sessionOptions.Value.IdleTimeout => GrantValidity.SessionEnded,
            { IsDisabled: true } => GrantValidity.UserDisabled,
            { ClientDisabled: true } => GrantValidity.ClientDisabled,
            _ => GrantValidity.Valid,
        };
        return new GrantState(validity, row.SessionId, row.UserId, row.ApplicationId, row.AuthTime, row.Amr);
    }

    /// <summary>Using an application counts as activity for the central session's idle timeout.</summary>
    public Task TouchSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        return db.UserSessions
            .Where(x => x.Id == sessionId && x.RevokedAt == null && x.LastSeenAt < now)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.LastSeenAt, now), cancellationToken);
    }
}

/// <summary>Remembered consent decisions (user × client × scopes).</summary>
public sealed class ConsentService(IamDbContext db, RevocationService revocation, AuditWriter audit, TimeProvider time)
{
    public async Task<bool> CoversAsync(Guid userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken)
    {
        var granted = await db.Consents.AsNoTracking()
            .Where(x => x.UserId == userId && x.ClientId == clientId && x.RevokedAt == null)
            .Select(x => x.Scopes)
            .SingleOrDefaultAsync(cancellationToken);
        if (granted is null)
        {
            return false;
        }

        var set = granted.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        return scopes.All(set.Contains);
    }

    /// <summary>Stages the decision (union with previously granted scopes) in the caller's unit of work.</summary>
    public async Task GrantAsync(Guid userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var existing = await db.Consents.SingleOrDefaultAsync(x => x.UserId == userId && x.ClientId == clientId && x.RevokedAt == null, cancellationToken);
        if (existing is null)
        {
            db.Consents.Add(new Consent
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ClientId = clientId,
                Scopes = string.Join(' ', scopes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)),
                GrantedAt = now,
                UpdatedAt = now,
            });
        }
        else
        {
            existing.Scopes = string.Join(' ', existing.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Union(scopes, StringComparer.Ordinal).Order(StringComparer.Ordinal));
            existing.UpdatedAt = now;
        }

        audit.Add("consent.granted", AuditOutcome.Success, AuditActor.User, userId.ToString(), "client", clientId);
    }

    /// <summary>
    /// Withdraws consent: the decision is removed and every grant (hence every token) the user gave this client is
    /// revoked in the same transaction. The next authorization request shows the consent screen again.
    /// </summary>
    public async Task<bool> RevokeAsync(Guid userId, string clientId, string actorType, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var updated = await db.Consents
            .Where(x => x.UserId == userId && x.ClientId == clientId && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.RevokedAt, now), cancellationToken);
        await revocation.RevokeUserClientGrantsAsync(userId, clientId, RevocationReason.ConsentRevoked, actorType, actorId, cancellationToken);
        if (updated > 0)
        {
            audit.Add("consent.revoked", AuditOutcome.Success, actorType, actorId, "client", clientId, $"user={userId}");
            await db.SaveChangesAsync(cancellationToken);
        }

        await scope.CommitAsync(cancellationToken);
        return updated > 0;
    }
}

/// <summary>Builds token identities. Only standard claims are issued; "amr" and "auth_time" come from the session row.</summary>
public static class TokenIdentity
{
    public static ClaimsIdentity ForUser(
        ApplicationUser user,
        DateTimeOffset authTime,
        IEnumerable<string> amr,
        ImmutableArray<string> scopes,
        IEnumerable<string> resources)
    {
        var identity = new ClaimsIdentity(Microsoft.IdentityModel.Tokens.TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, user.Id.ToString());
        identity.SetClaim(Claims.Name, user.DisplayName.Length > 0 ? user.DisplayName : user.Email);
        identity.SetClaim(Claims.PreferredUsername, user.Email);
        identity.SetClaim(Claims.Email, user.Email);
        identity.SetClaim(Claims.EmailVerified, user.EmailConfirmed);
        identity.SetClaim(Claims.AuthenticationTime, authTime.ToUnixTimeSeconds());
        identity.SetClaims(Claims.AuthenticationMethodReference, [.. amr]);
        identity.SetScopes(scopes);
        identity.SetResources(resources);
        identity.SetDestinations(Destinations);
        return identity;
    }

    /// <summary>Machine identity: the subject is the client itself. No user claim and no identity token.</summary>
    public static ClaimsIdentity ForClient(string clientId, ImmutableArray<string> scopes, IEnumerable<string> resources)
    {
        var identity = new ClaimsIdentity(Microsoft.IdentityModel.Tokens.TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, clientId);
        identity.SetScopes(scopes);
        identity.SetResources(resources);
        identity.SetDestinations(static _ => [OpenIddictConstants.Destinations.AccessToken]);
        return identity;
    }

    /// <summary>Claim minimisation: a claim only goes where its scope allows it.</summary>
    private static IEnumerable<string> Destinations(Claim claim)
    {
        var identity = claim.Subject!;
        switch (claim.Type)
        {
            case Claims.Subject:
            case Claims.AuthenticationTime:
            case Claims.AuthenticationMethodReference:
                yield return OpenIddictConstants.Destinations.AccessToken;
                if (identity.HasScope(Scopes.OpenId))
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                }

                yield break;

            case Claims.Name:
            case Claims.PreferredUsername:
                if (identity.HasScope(Scopes.OpenId) && identity.HasScope(Scopes.Profile))
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                }

                yield break;

            case Claims.Email:
            case Claims.EmailVerified:
                if (identity.HasScope(Scopes.OpenId) && identity.HasScope(Scopes.Email))
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                }

                yield break;

            default:
                yield break;
        }
    }
}
