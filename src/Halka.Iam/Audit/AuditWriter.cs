using System.Diagnostics;
using Halka.Iam.Data;

namespace Halka.Iam.Audit;

public static class AuditActor
{
    public const string User = "user";
    public const string Client = "client";
    public const string System = "system";
    public const string Anonymous = "anonymous";
}

public static class AuditOutcome
{
    public const string Success = "success";
    public const string Failure = "failure";
    public const string Denied = "denied";
}

/// <summary>
/// Adds audit rows to the current unit of work. Callers pass identifiers only; values such as passwords, tokens,
/// TOTP secrets, recovery codes, e-mail addresses or IP addresses must never be passed as reason or target.
/// </summary>
public sealed class AuditWriter(IamDbContext db, TimeProvider time)
{
    /// <summary>Stages an audit row; it is committed together with the surrounding business change.</summary>
    public void Add(
        string action,
        string outcome,
        string actorType,
        string? actorId,
        string? targetType = null,
        string? targetId = null,
        string? reason = null)
    {
        db.AuditEvents.Add(new AuditEvent
        {
            OccurredAt = time.GetUtcNow(),
            ActorType = actorType,
            ActorId = actorId,
            Action = action,
            TargetType = targetType,
            TargetId = targetId,
            Outcome = outcome,
            CorrelationId = Activity.Current?.TraceId.ToString(),
            Reason = reason is { Length: > 200 } ? reason[..200] : reason,
        });
    }

    public async Task WriteAsync(
        string action,
        string outcome,
        string actorType,
        string? actorId,
        string? targetType = null,
        string? targetId = null,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        Add(action, outcome, actorType, actorId, targetType, targetId, reason);
        await db.SaveChangesAsync(cancellationToken);
    }
}
