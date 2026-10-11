namespace Halka.Iam.Data;

public static class MfaStatus
{
    /// <summary>Enrollment started; the secret is not usable for sign-in until a valid code confirms it.</summary>
    public const string Pending = "pending";
    public const string Active = "active";
}

/// <summary>TOTP authenticator of a user. The shared secret is wrapped with Data Protection.</summary>
public sealed class UserMfa
{
    public Guid UserId { get; set; }

    public byte[] ProtectedSecret { get; set; } = [];

    public string Status { get; set; } = MfaStatus.Pending;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ActivatedAt { get; set; }

    /// <summary>
    /// Highest TOTP time step that was accepted. A code is only accepted when its step is greater, which makes
    /// each time step single-use even under concurrent attempts.
    /// </summary>
    public long LastAcceptedStep { get; set; }
}

/// <summary>Single-use recovery code; only a SHA-256 hash of the random value is stored.</summary>
public sealed class RecoveryCode
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public byte[] CodeHash { get; set; } = [];

    public Guid BatchId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? UsedAt { get; set; }
}

public static class MfaChallengePurpose
{
    public const string Login = "login";
    public const string StepUp = "step_up";
}

/// <summary>
/// A pending second-factor prompt. It is bound to one user, expires quickly, allows a limited number of attempts
/// and can be completed once. Holding its identifier is not an authenticated session.
/// </summary>
public sealed class MfaChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public string Purpose { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public int Attempts { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}
