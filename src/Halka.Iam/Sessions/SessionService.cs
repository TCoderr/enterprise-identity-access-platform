using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Sessions;

public readonly record struct SessionLookup(CurrentSession? Session, string? ExpiredReason);

/// <summary>Central session state. Every request is validated against the database; nothing is cached.</summary>
public sealed class SessionService(IamDbContext db, TimeProvider time, IOptions<CentralSessionOptions> options)
{
    private readonly CentralSessionOptions _options = options.Value;

    /// <summary>Stages a new session row in the current unit of work.</summary>
    public UserSession Stage(ApplicationUser user, IReadOnlyCollection<string> amr, string clientLabel)
    {
        var now = time.GetUtcNow();
        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            CreatedAt = now,
            AuthTime = now,
            Amr = Amr.Join(amr),
            PasswordVerifiedAt = now,
            MfaVerifiedAt = amr.Contains(Amr.Mfa) ? now : null,
            LastSeenAt = now,
            AbsoluteExpiresAt = now + _options.AbsoluteLifetime,
            ClientLabel = clientLabel,
        };
        db.UserSessions.Add(session);
        return session;
    }

    /// <summary>Sessions that are neither revoked nor expired at <paramref name="now"/>.</summary>
    public IQueryable<UserSession> Active(DateTimeOffset now)
    {
        var idleCutoff = now - _options.IdleTimeout;
        return db.UserSessions.Where(x => x.RevokedAt == null && x.AbsoluteExpiresAt > now && x.LastSeenAt > idleCutoff);
    }

    /// <summary>
    /// Loads the session with its user and current roles. Returns no session when it is revoked, expired, unknown or
    /// when the user is disabled. When the session merely timed out, the reason is returned so it can be ended.
    /// </summary>
    public async Task<SessionLookup> LoadAsync(Guid sessionId, Guid userId, CancellationToken cancellationToken)
    {
        var row = await db.UserSessions.AsNoTracking()
            .Where(x => x.Id == sessionId && x.UserId == userId)
            .Select(x => new
            {
                Session = x,
                x.User.Email,
                x.User.DisplayName,
                x.User.IsDisabled,
            })
            .SingleOrDefaultAsync(cancellationToken);
        if (row is null || row.Session.RevokedAt is not null || row.IsDisabled)
        {
            return default;
        }

        var now = time.GetUtcNow();
        if (now >= row.Session.AbsoluteExpiresAt)
        {
            return new SessionLookup(null, SessionEndReason.AbsoluteTimeout);
        }

        if (now - row.Session.LastSeenAt >= _options.IdleTimeout)
        {
            return new SessionLookup(null, SessionEndReason.IdleTimeout);
        }

        var roles = await (
            from userRole in db.UserRoles
            join role in db.Roles on userRole.RoleId equals role.Id
            where userRole.UserId == userId
            select role.Name!).ToListAsync(cancellationToken);

        if (now - row.Session.LastSeenAt >= _options.TouchInterval)
        {
            await db.UserSessions
                .Where(x => x.Id == sessionId && x.RevokedAt == null)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.LastSeenAt, now), cancellationToken);
        }

        var mfaEnabled = await db.UserMfa.AnyAsync(x => x.UserId == userId && x.Status == MfaStatus.Active, cancellationToken);
        var session = row.Session;
        return new SessionLookup(
            new CurrentSession(
                session.Id,
                session.UserId,
                row.Email ?? string.Empty,
                row.DisplayName,
                session.AuthTime,
                Amr.Split(session.Amr),
                session.PasswordVerifiedAt,
                session.MfaVerifiedAt,
                session.AbsoluteExpiresAt,
                roles,
                MfaEnabled: mfaEnabled),
            null);
    }
}

/// <summary>Creates and ends the browser's central session cookie.</summary>
public sealed class SessionSignIn(
    IamDbContext db,
    SessionService sessions,
    RevocationService revocation,
    AuditWriter audit)
{
    /// <summary>
    /// Starts a new session. A fresh identifier is always issued and any session the browser presented before is
    /// ended, so a pre-authentication or stolen identifier can never be promoted (session fixation guard).
    /// </summary>
    public async Task<UserSession> SignInAsync(
        HttpContext http,
        ApplicationUser user,
        IReadOnlyCollection<string> amr,
        CancellationToken cancellationToken)
    {
        if (http.GetCurrentSession() is { } previous)
        {
            await revocation.EndSessionAsync(previous.Id, SessionEndReason.Replaced, AuditActor.User, previous.UserId.ToString(), cancellationToken);
        }

        var session = sessions.Stage(user, amr, ClientLabel.FromUserAgent(http.Request.Headers.UserAgent));
        audit.Add("session.started", AuditOutcome.Success, AuditActor.User, user.Id.ToString(), "session", session.Id.ToString(), session.Amr);
        await db.SaveChangesAsync(cancellationToken);

        await http.SignInAsync(
            SessionDefaults.Scheme,
            SessionPrincipal.ForTicket(user.Id, session.Id),
            new AuthenticationProperties
            {
                IsPersistent = false,
                IssuedUtc = session.CreatedAt,
                ExpiresUtc = session.AbsoluteExpiresAt,
                AllowRefresh = false,
            });
        return session;
    }

    /// <summary>Ends the current central session on the server and removes the cookie.</summary>
    public async Task SignOutAsync(HttpContext http, string reason, CancellationToken cancellationToken)
    {
        if (http.GetCurrentSession() is { } current)
        {
            await revocation.EndSessionAsync(current.Id, reason, AuditActor.User, current.UserId.ToString(), cancellationToken);
        }

        await http.SignOutAsync(SessionDefaults.Scheme);
    }
}

public static class CurrentSessionExtensions
{
    private static readonly object Key = typeof(CurrentSession);

    public static CurrentSession? GetCurrentSession(this HttpContext http)
        => http.Items.TryGetValue(Key, out var value) ? value as CurrentSession : null;

    /// <summary>Removes the session cookie of this browser (the server-side session is ended separately).</summary>
    public static Task SignOutIfPresentAsync(this HttpContext http) => http.SignOutAsync(SessionDefaults.Scheme);

    public static CurrentSession RequireCurrentSession(this HttpContext http)
        => http.GetCurrentSession() ?? throw new InvalidOperationException("The request has no validated central session.");

    internal static void SetCurrentSession(this HttpContext http, CurrentSession? session)
    {
        if (session is null)
        {
            http.Items.Remove(Key);
        }
        else
        {
            http.Items[Key] = session;
        }
    }
}
