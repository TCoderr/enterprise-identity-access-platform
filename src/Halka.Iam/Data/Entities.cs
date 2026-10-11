using Microsoft.AspNetCore.Identity;

namespace Halka.Iam.Data;

public sealed class ApplicationUser : IdentityUser<Guid>
{
    public string DisplayName { get; set; } = string.Empty;

    public bool IsDisabled { get; set; }

    public DateTimeOffset? DisabledAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class ApplicationRole : IdentityRole<Guid>
{
    public ApplicationRole()
    {
    }

    public ApplicationRole(string name) : base(name)
    {
        Id = Guid.NewGuid();
    }
}

/// <summary>Central (OP) browser session. The cookie only carries the identifier; this row is authoritative.</summary>
public sealed class UserSession
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public ApplicationUser User { get; set; } = null!;

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Time of the last full primary authentication (OIDC auth_time).</summary>
    public DateTimeOffset AuthTime { get; set; }

    /// <summary>Space-delimited RFC 8176 method references that were actually performed.</summary>
    public string Amr { get; set; } = string.Empty;

    public DateTimeOffset PasswordVerifiedAt { get; set; }

    public DateTimeOffset? MfaVerifiedAt { get; set; }

    public DateTimeOffset LastSeenAt { get; set; }

    public DateTimeOffset AbsoluteExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }

    /// <summary>Coarse, non-identifying device label such as "Chrome on Windows".</summary>
    public string ClientLabel { get; set; } = string.Empty;
}

public static class OneTimeTokenPurpose
{
    public const string ConfirmEmail = "confirm_email";
    public const string ResetPassword = "reset_password";
}

/// <summary>Single-use, expiring account token. Only the SHA-256 hash of the random value is stored.</summary>
public sealed class OneTimeToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public string Purpose { get; set; } = string.Empty;

    public byte[] TokenHash { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}

public sealed class OutboxMessage
{
    public Guid Id { get; set; }

    public string Kind { get; set; } = string.Empty;

    /// <summary>Data Protection protected payload (recipient and link); never stored in clear text.</summary>
    public byte[] ProtectedPayload { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset AvailableAt { get; set; }

    public int Attempts { get; set; }

    public string? LeaseOwner { get; set; }

    public DateTimeOffset? LeaseUntil { get; set; }

    /// <summary>Fencing token: incremented on every lease; completion is only accepted for the current value.</summary>
    public long LeaseVersion { get; set; }

    public DateTimeOffset? DeliveredAt { get; set; }

    public DateTimeOffset? DeadAt { get; set; }

    public string? LastErrorCode { get; set; }
}

/// <summary>Append-only security audit record. Contains identifiers only: no e-mail, IP address, token or secret.</summary>
public sealed class AuditEvent
{
    public long Id { get; set; }

    public DateTimeOffset OccurredAt { get; set; }

    public string ActorType { get; set; } = string.Empty;

    public string? ActorId { get; set; }

    public string Action { get; set; } = string.Empty;

    public string? TargetType { get; set; }

    public string? TargetId { get; set; }

    public string Outcome { get; set; } = string.Empty;

    public string? CorrelationId { get; set; }

    public string? Reason { get; set; }
}

public sealed class DataMarker
{
    public string Key { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;
}
