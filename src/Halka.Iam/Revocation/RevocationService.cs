using Halka.Iam.Audit;
using Halka.Iam.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using OpenIddict.Abstractions;

namespace Halka.Iam.Revocation;

/// <summary>
/// Single place for every revocation rule. Pages and endpoints call these methods; they never update session, grant
/// or token state directly. Each method applies its effect and its audit record in one database transaction (it
/// joins the caller's transaction when one is already open). The database is authoritative: protocol endpoints and
/// introspection read this state on every request, so effects are immediate.
/// </summary>
public sealed class RevocationService(IamDbContext db, AuditWriter audit, TimeProvider time, Halka.Iam.Ops.IamMetrics metrics)
{
    /// <summary>Ends one central session and revokes the grants (and with them all tokens) issued from it.</summary>
    public async Task<int> EndSessionAsync(Guid sessionId, string reason, string actorType, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var ended = await db.UserSessions
            .Where(x => x.Id == sessionId && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, reason), cancellationToken);
        var grants = await RevokeGrantsAsync(db.SessionGrants.Where(x => x.SessionId == sessionId), RevocationReason.SessionEnded, now, cancellationToken);
        if (ended == 1)
        {
            // The affected account is recorded so the event can be found by user as well as by session.
            var userId = await db.UserSessions.Where(x => x.Id == sessionId).Select(x => x.UserId).SingleAsync(cancellationToken);
            audit.Add("session.ended", AuditOutcome.Success, actorType, actorId, "session", sessionId.ToString(), $"{reason}; user={userId}; grants={grants}");
            await db.SaveChangesAsync(cancellationToken);
        }

        await scope.CommitAsync(cancellationToken);
        metrics.Revocation("session");
        return ended;
    }

    /// <summary>Ends every active session of a user (optionally keeping one) and revokes the grants of the ended sessions.</summary>
    public async Task<int> EndAllSessionsAsync(Guid userId, string reason, string actorType, string? actorId, Guid? exceptSessionId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var ended = await db.UserSessions
            .Where(x => x.UserId == userId && x.RevokedAt == null && (exceptSessionId == null || x.Id != exceptSessionId))
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, reason), cancellationToken);
        var grants = await RevokeGrantsAsync(
            db.SessionGrants.Where(x => x.UserId == userId && (exceptSessionId == null || x.SessionId != exceptSessionId)),
            RevocationReason.SessionEnded, now, cancellationToken);
        audit.Add("session.ended_all", AuditOutcome.Success, actorType, actorId, "user", userId.ToString(), $"{reason}; sessions={ended}; grants={grants}");
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return ended;
    }

    /// <summary>
    /// Closes sessions that timed out without anyone signing out. They were already unusable (every request checks
    /// the timeouts); closing them records the end and revokes their grants, so retention can remove the tokens.
    /// </summary>
    public async Task<int> CloseExpiredSessionsAsync(TimeSpan idleTimeout, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var idleCutoff = now - idleTimeout;
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var ids = await db.UserSessions
            .Where(x => x.RevokedAt == null && (x.AbsoluteExpiresAt <= now || x.LastSeenAt <= idleCutoff))
            .Select(x => x.Id)
            .ToListAsync(cancellationToken);
        if (ids.Count == 0)
        {
            return 0;
        }

        var closed = await db.UserSessions
            .Where(x => ids.Contains(x.Id) && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, x => x.AbsoluteExpiresAt <= now ? Sessions.SessionEndReason.AbsoluteTimeout : Sessions.SessionEndReason.IdleTimeout), cancellationToken);
        var grants = await RevokeGrantsAsync(db.SessionGrants.Where(x => ids.Contains(x.SessionId)), RevocationReason.SessionEnded, now, cancellationToken);
        audit.Add("session.expired_closed", AuditOutcome.Success, AuditActor.System, null, "installation", null, $"sessions={closed}; grants={grants}");
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return closed;
    }

    /// <summary>Revokes one grant: its authorization entry and every code, access and refresh token under it.</summary>
    public async Task<int> RevokeGrantAsync(Guid authorizationId, string reason, string actorType, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var revoked = await RevokeGrantsAsync(db.SessionGrants.Where(x => x.AuthorizationId == authorizationId), reason, now, cancellationToken);
        if (revoked > 0)
        {
            var owner = await db.SessionGrants.Where(x => x.AuthorizationId == authorizationId).Select(x => new { x.UserId, x.ClientId }).SingleAsync(cancellationToken);
            audit.Add("grant.revoked", AuditOutcome.Success, actorType, actorId, "grant", authorizationId.ToString(), $"{reason}; user={owner.UserId}; client={owner.ClientId}");
            await db.SaveChangesAsync(cancellationToken);
        }

        await scope.CommitAsync(cancellationToken);
        metrics.Revocation("grant");
        return revoked;
    }

    /// <summary>Revokes every grant a user gave to one client, across all sessions.</summary>
    public async Task<int> RevokeUserClientGrantsAsync(Guid userId, string clientId, string reason, string actorType, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var revoked = await RevokeGrantsAsync(db.SessionGrants.Where(x => x.UserId == userId && x.ClientId == clientId), reason, now, cancellationToken);
        audit.Add("grant.revoked_for_client", AuditOutcome.Success, actorType, actorId, "user", userId.ToString(), $"{reason}; client={clientId}; grants={revoked}");
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return revoked;
    }

    /// <summary>
    /// Revokes everything a client holds: user grants and tokens that are bound to the client alone
    /// (client_credentials tokens have no grant).
    /// </summary>
    public async Task<int> RevokeClientAsync(Guid applicationId, string clientId, string reason, string actorType, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var revoked = await RevokeGrantsAsync(db.SessionGrants.Where(x => x.ApplicationId == applicationId), reason, now, cancellationToken);
        var stamp = Guid.NewGuid().ToString();
        var tokens = await db.Tokens
            .Where(x => x.Application != null && x.Application.Id == applicationId && x.Status != OpenIddictConstants.Statuses.Revoked)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.Status, OpenIddictConstants.Statuses.Revoked)
                .SetProperty(x => x.ConcurrencyToken, stamp), cancellationToken);
        audit.Add("client.tokens_revoked", AuditOutcome.Success, actorType, actorId, "client", clientId, $"{reason}; grants={revoked}; tokens={tokens}");
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return revoked;
    }

    /// <summary>Revokes every grant and token of the installation (signing or encryption key compromise).</summary>
    public async Task<int> RevokeEverythingAsync(string reason, string actorType, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var revoked = await RevokeGrantsAsync(db.SessionGrants, reason, now, cancellationToken);
        var stamp = Guid.NewGuid().ToString();
        var tokens = await db.Tokens
            .Where(x => x.Status != OpenIddictConstants.Statuses.Revoked)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.Status, OpenIddictConstants.Statuses.Revoked)
                .SetProperty(x => x.ConcurrencyToken, stamp), cancellationToken);
        await db.Authorizations
            .Where(x => x.Status != OpenIddictConstants.Statuses.Revoked)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.Status, OpenIddictConstants.Statuses.Revoked)
                .SetProperty(x => x.ConcurrencyToken, stamp), cancellationToken);
        audit.Add("grant.revoked_all", AuditOutcome.Success, actorType, actorId, "installation", null, $"{reason}; grants={revoked}; tokens={tokens}");
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return revoked;
    }

    /// <summary>
    /// Marks the selected grants, their OpenIddict authorization entries and all their tokens as revoked. The
    /// authorization entry is what the library checks for every token of a grant, so its concurrency token is
    /// changed as well: no concurrent library update based on a stale read can bring the grant back. Token rows
    /// keep their concurrency token; a request that is writing tokens of this grant at the same moment completes
    /// normally, and what it writes is inert because its authorization is revoked.
    /// </summary>
    private async Task<int> RevokeGrantsAsync(IQueryable<SessionGrant> selection, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var ids = await selection.Where(x => x.RevokedAt == null).Select(x => x.AuthorizationId).ToListAsync(cancellationToken);
        if (ids.Count == 0)
        {
            return 0;
        }

        var stamp = Guid.NewGuid().ToString();
        await db.SessionGrants
            .Where(x => ids.Contains(x.AuthorizationId) && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, reason), cancellationToken);
        await db.Authorizations
            .Where(x => ids.Contains(x.Id) && x.Status != OpenIddictConstants.Statuses.Revoked)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.Status, OpenIddictConstants.Statuses.Revoked)
                .SetProperty(x => x.ConcurrencyToken, stamp), cancellationToken);
        await db.Tokens
            .Where(x => x.Authorization != null && ids.Contains(x.Authorization.Id) && x.Status != OpenIddictConstants.Statuses.Revoked)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, OpenIddictConstants.Statuses.Revoked), cancellationToken);
        return ids.Count;
    }
}

/// <summary>Starts a transaction unless the context already has one; only the owner commits or rolls back.</summary>
public sealed class TransactionScope : IAsyncDisposable
{
    private readonly IDbContextTransaction? _owned;

    private TransactionScope(IDbContextTransaction? owned) => _owned = owned;

    public static async Task<TransactionScope> BeginAsync(DbContext db, CancellationToken cancellationToken)
        => new(db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(cancellationToken) : null);

    public Task CommitAsync(CancellationToken cancellationToken)
        => _owned is null ? Task.CompletedTask : _owned.CommitAsync(cancellationToken);

    public ValueTask DisposeAsync() => _owned is null ? ValueTask.CompletedTask : _owned.DisposeAsync();
}
