using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Protocol;
using Halka.Iam.Revocation;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Iam.Clients;

public sealed record ClientRegistration(
    string ClientId,
    string DisplayName,
    string Kind,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    IReadOnlyList<string> Scopes,
    string ConsentType);

public sealed record ScopeRegistration(string Name, string DisplayName, string Description, string? Resource);

public sealed class ClientValidationException(IReadOnlyList<string> errors) : Exception(string.Join(" ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}

/// <summary>Pure validation rules of client and scope registrations (no I/O).</summary>
public static partial class ClientRules
{
    public static readonly IReadOnlyList<string> IdentityScopes = [Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.OfflineAccess];

    public static readonly IReadOnlyList<string> ConsentTypesAllowed = [ConsentTypes.Explicit, ConsentTypes.Systematic, ConsentTypes.Implicit];

    public static IReadOnlyList<string> Validate(ClientRegistration registration, IReadOnlySet<string> knownScopes)
    {
        var errors = new List<string>();
        if (!ClientIdPattern().IsMatch(registration.ClientId))
        {
            errors.Add("The client identifier must be 3 to 64 characters: lower-case letters, digits and dashes.");
        }

        if (string.IsNullOrWhiteSpace(registration.DisplayName) || registration.DisplayName.Length > 100)
        {
            errors.Add("The display name is required and can be at most 100 characters.");
        }

        if (!ClientKind.All.Contains(registration.Kind))
        {
            errors.Add("Unknown client kind.");
            return errors;
        }

        if (!ConsentTypesAllowed.Contains(registration.ConsentType))
        {
            errors.Add("Unknown consent policy.");
        }

        foreach (var uri in registration.RedirectUris.Concat(registration.PostLogoutRedirectUris))
        {
            if (ValidateRegisteredUri(uri) is { } problem)
            {
                errors.Add($"'{uri}': {problem}");
            }
        }

        foreach (var scope in registration.Scopes.Where(scope => !knownScopes.Contains(scope) && !IdentityScopes.Contains(scope)))
        {
            errors.Add($"Scope '{scope}' is not registered.");
        }

        switch (registration.Kind)
        {
            case ClientKind.Web:
                if (registration.RedirectUris.Count == 0)
                {
                    errors.Add("A web client needs at least one redirect URI.");
                }

                if (!registration.Scopes.Contains(Scopes.OpenId))
                {
                    errors.Add("A web client must be allowed the 'openid' scope.");
                }

                break;

            case ClientKind.Machine:
                if (registration.RedirectUris.Count > 0 || registration.PostLogoutRedirectUris.Count > 0)
                {
                    errors.Add("A machine client cannot have redirect URIs.");
                }

                if (registration.Scopes.Any(IdentityScopes.Contains))
                {
                    errors.Add("A machine client cannot be allowed identity scopes (openid, profile, email, offline_access).");
                }

                break;

            case ClientKind.Resource:
                if (registration.RedirectUris.Count > 0 || registration.PostLogoutRedirectUris.Count > 0 || registration.Scopes.Count > 0)
                {
                    errors.Add("A resource server only introspects tokens; it has no redirect URIs or scopes.");
                }

                break;
        }

        return errors;
    }

    /// <summary>
    /// Redirect and post-logout URIs are compared as exact strings by the protocol library. Registration therefore
    /// only accepts absolute https URIs without fragment, user info or wildcard characters.
    /// </summary>
    public static string? ValidateRegisteredUri(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 400 || value != value.Trim())
        {
            return "must be a non-empty URI of at most 400 characters without surrounding spaces.";
        }

        if (value.Contains('*', StringComparison.Ordinal))
        {
            return "wildcards are not allowed.";
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return "must be an absolute URI.";
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return "must use https.";
        }

        if (!string.IsNullOrEmpty(uri.Fragment) || value.Contains('#', StringComparison.Ordinal))
        {
            return "must not contain a fragment.";
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return "must not contain user information.";
        }

        return null;
    }

    public static IReadOnlyList<string> ValidateScope(ScopeRegistration scope)
    {
        var errors = new List<string>();
        if (!ScopePattern().IsMatch(scope.Name) || IdentityScopes.Contains(scope.Name))
        {
            errors.Add("The scope name must be 3 to 64 characters (lower-case letters, digits, dot, dash, underscore) and must not be a reserved identity scope.");
        }

        if (string.IsNullOrWhiteSpace(scope.DisplayName) || scope.DisplayName.Length > 100)
        {
            errors.Add("The display name is required and can be at most 100 characters.");
        }

        if (scope.Description.Length > 300)
        {
            errors.Add("The description can be at most 300 characters.");
        }

        if (scope.Resource is not null && !ClientIdPattern().IsMatch(scope.Resource))
        {
            errors.Add("The resource must be the client identifier of a resource server.");
        }

        return errors;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")]
    private static partial Regex ClientIdPattern();

    [GeneratedRegex("^[a-z][a-z0-9._-]{1,62}[a-z0-9]$")]
    private static partial Regex ScopePattern();
}

/// <summary>
/// Client and scope registration. Client secrets are generated here (256 bits from the system CSPRNG), returned
/// exactly once to the caller and stored only as the hash computed by the OpenIddict application manager.
/// </summary>
public sealed class ClientRegistry(
    IamDbContext db,
    IOpenIddictApplicationManager applications,
    IOpenIddictScopeManager scopes,
    RevocationService revocation,
    AuditWriter audit,
    TimeProvider time,
    IOptions<ProtocolOptions> options)
{
    public static string GenerateSecret() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    public async Task<IReadOnlySet<string>> KnownScopesAsync(CancellationToken cancellationToken)
        => (await db.Scopes.AsNoTracking().Select(x => x.Name!).ToListAsync(cancellationToken)).ToHashSet(StringComparer.Ordinal);

    /// <summary>Registers a client and returns its clear-text secret for one-time display.</summary>
    public async Task<string> CreateAsync(ClientRegistration registration, string? secret, Guid? actorId, CancellationToken cancellationToken)
    {
        var errors = ClientRules.Validate(registration, await KnownScopesAsync(cancellationToken)).ToList();
        if (errors.Count == 0 && await applications.FindByClientIdAsync(registration.ClientId, cancellationToken) is not null)
        {
            errors.Add("A client with this identifier already exists.");
        }

        if (errors.Count > 0)
        {
            throw new ClientValidationException(errors);
        }

        secret ??= GenerateSecret();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var application = (OpenIddictEntityFrameworkCoreApplication<Guid>)await applications.CreateAsync(Describe(registration, secret), cancellationToken);
        db.ClientSettings.Add(new ClientSettings
        {
            ApplicationId = application.Id,
            Kind = registration.Kind,
            CreatedAt = time.GetUtcNow(),
            CreatedBy = actorId,
        });
        audit.Add("client.created", AuditOutcome.Success, actorId is null ? AuditActor.System : AuditActor.User, actorId?.ToString(), "client", registration.ClientId, registration.Kind);
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return secret;
    }

    /// <summary>Replaces display name, URIs, scopes and consent policy. The identifier, kind and secret are not changed.</summary>
    public async Task UpdateAsync(ClientRegistration registration, Guid? actorId, CancellationToken cancellationToken)
    {
        var application = await FindAsync(registration.ClientId, cancellationToken);
        var settings = await db.ClientSettings.SingleAsync(x => x.ApplicationId == application.Id, cancellationToken);
        var effective = registration with { Kind = settings.Kind };
        var errors = ClientRules.Validate(effective, await KnownScopesAsync(cancellationToken));
        if (errors.Count > 0)
        {
            throw new ClientValidationException(errors);
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);
        var updated = Describe(effective, secret: null);
        descriptor.DisplayName = updated.DisplayName;
        descriptor.ConsentType = updated.ConsentType;
        descriptor.RedirectUris.Clear();
        descriptor.RedirectUris.UnionWith(updated.RedirectUris);
        descriptor.PostLogoutRedirectUris.Clear();
        descriptor.PostLogoutRedirectUris.UnionWith(updated.PostLogoutRedirectUris);
        descriptor.Permissions.Clear();
        descriptor.Permissions.UnionWith(updated.Permissions);
        descriptor.Requirements.Clear();
        descriptor.Requirements.UnionWith(updated.Requirements);

        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        await applications.UpdateAsync(application, descriptor, cancellationToken);
        audit.Add("client.updated", AuditOutcome.Success, actorId is null ? AuditActor.System : AuditActor.User, actorId?.ToString(), "client", registration.ClientId);
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Issues a new secret. The previous secret keeps working until the end of the grace window (zero means it
    /// stops immediately); after that it is rejected. Existing tokens are not affected by a rotation.
    /// </summary>
    public async Task<string> RotateSecretAsync(string clientId, TimeSpan grace, Guid? actorId, CancellationToken cancellationToken)
    {
        if (grace < TimeSpan.Zero || grace > options.Value.MaximumClientSecretGrace)
        {
            throw new ClientValidationException([$"The grace window must be between 0 and {options.Value.MaximumClientSecretGrace.TotalHours:0} hours."]);
        }

        var application = await FindAsync(clientId, cancellationToken);
        var now = time.GetUtcNow();
        var secret = GenerateSecret();

        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        if (grace > TimeSpan.Zero && !string.IsNullOrEmpty(application.ClientSecret))
        {
            db.ClientSecrets.Add(new ClientSecret
            {
                Id = Guid.NewGuid(),
                ApplicationId = application.Id,
                SecretHash = application.ClientSecret,
                CreatedAt = now,
                NotAfter = now + grace,
                CreatedBy = actorId,
            });
        }
        else
        {
            // No grace: any secret still in an earlier grace window stops working as well.
            await db.ClientSecrets.Where(x => x.ApplicationId == application.Id && x.RevokedAt == null)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.RevokedAt, now), cancellationToken);
        }

        await applications.UpdateAsync(application, secret, cancellationToken);
        audit.Add("client.secret_rotated", AuditOutcome.Success, actorId is null ? AuditActor.System : AuditActor.User, actorId?.ToString(), "client", clientId, $"grace_seconds={grace.TotalSeconds:0}");
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return secret;
    }

    /// <summary>Disables a client and revokes everything it holds, or enables it again (revoked tokens stay revoked).</summary>
    public async Task SetDisabledAsync(string clientId, bool disabled, Guid? actorId, CancellationToken cancellationToken)
    {
        var application = await FindAsync(clientId, cancellationToken);
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var changed = await db.ClientSettings
            .Where(x => x.ApplicationId == application.Id && x.IsDisabled != disabled)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.IsDisabled, disabled)
                .SetProperty(x => x.DisabledAt, disabled ? now : (DateTimeOffset?)null), cancellationToken);
        if (changed == 1)
        {
            if (disabled)
            {
                await revocation.RevokeClientAsync(application.Id, clientId, RevocationReason.ClientDisabled, AuditActor.User, actorId?.ToString(), cancellationToken);
            }

            audit.Add(disabled ? "client.disabled" : "client.enabled", AuditOutcome.Success, actorId is null ? AuditActor.System : AuditActor.User, actorId?.ToString(), "client", clientId);
            await db.SaveChangesAsync(cancellationToken);
        }

        await scope.CommitAsync(cancellationToken);
    }

    public async Task CreateScopeAsync(ScopeRegistration registration, Guid? actorId, CancellationToken cancellationToken)
    {
        var errors = ClientRules.ValidateScope(registration).ToList();
        if (errors.Count == 0 && await scopes.FindByNameAsync(registration.Name, cancellationToken) is not null)
        {
            errors.Add("A scope with this name already exists.");
        }

        if (errors.Count > 0)
        {
            throw new ClientValidationException(errors);
        }

        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = registration.Name,
            DisplayName = registration.DisplayName,
            Description = registration.Description,
        };
        if (registration.Resource is not null)
        {
            descriptor.Resources.Add(registration.Resource);
        }

        await scopes.CreateAsync(descriptor, cancellationToken);
        await audit.WriteAsync("scope.created", AuditOutcome.Success, actorId is null ? AuditActor.System : AuditActor.User, actorId?.ToString(), "scope", registration.Name, cancellationToken: cancellationToken);
    }

    public async Task<bool> IsDisabledAsync(Guid applicationId, CancellationToken cancellationToken)
        => await db.ClientSettings.AsNoTracking().Where(x => x.ApplicationId == applicationId).Select(x => (bool?)x.IsDisabled).SingleOrDefaultAsync(cancellationToken) ?? true;

    private async Task<OpenIddictEntityFrameworkCoreApplication<Guid>> FindAsync(string clientId, CancellationToken cancellationToken)
        => await applications.FindByClientIdAsync(clientId, cancellationToken) as OpenIddictEntityFrameworkCoreApplication<Guid>
           ?? throw new ClientValidationException(["The client does not exist."]);

    /// <summary>Least-privilege permission set for each client kind.</summary>
    internal static OpenIddictApplicationDescriptor Describe(ClientRegistration registration, string? secret)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = registration.ClientId,
            ClientSecret = secret,
            DisplayName = registration.DisplayName,
            ClientType = ClientTypes.Confidential,
            ApplicationType = ApplicationTypes.Web,
            ConsentType = registration.Kind == ClientKind.Web ? registration.ConsentType : ConsentTypes.Implicit,
        };

        switch (registration.Kind)
        {
            case ClientKind.Web:
                descriptor.Permissions.UnionWith(
                [
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Revocation,
                    Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                ]);
                if (registration.Scopes.Contains(Scopes.OfflineAccess))
                {
                    descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
                }

                descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
                foreach (var uri in registration.RedirectUris)
                {
                    descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
                }

                foreach (var uri in registration.PostLogoutRedirectUris)
                {
                    descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
                }

                break;

            case ClientKind.Machine:
                descriptor.Permissions.UnionWith(
                [
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.ClientCredentials,
                ]);
                break;

            case ClientKind.Resource:
                descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
                break;
        }

        foreach (var scopeName in registration.Scopes.Where(name => name is not (Scopes.OpenId or Scopes.OfflineAccess)))
        {
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + scopeName);
        }

        return descriptor;
    }
}
