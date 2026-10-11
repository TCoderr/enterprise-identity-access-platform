using System.Security.Cryptography;
using System.Text;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;

namespace Halka.Iam.Mfa;

public sealed class MfaOptions
{
    public const string SectionName = "Mfa";

    public string Issuer { get; set; } = "Halka ID";

    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public int MaxAttemptsPerChallenge { get; set; } = 5;

    public int RecoveryCodeCount { get; set; } = 10;
}

/// <summary>
/// RFC 6238 time-based one-time passwords. All cryptography is done by Otp.NET; this class only chooses the
/// parameters (SHA-1, 6 digits, 30 seconds, one step of clock skew either way) and reports which time step matched.
/// </summary>
public static class TotpCodes
{
    public const int StepSeconds = 30;
    public const int Digits = 6;
    private static readonly VerificationWindow Window = new(previous: 1, future: 1);

    public static byte[] GenerateSecret() => KeyGeneration.GenerateRandomKey(20);

    public static string ToBase32(byte[] secret) => Base32Encoding.ToString(secret);

    /// <summary>Key URI understood by authenticator applications (shown as a QR code and as text).</summary>
    public static string ProvisioningUri(string issuer, string account, byte[] secret)
        => $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={ToBase32(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";

    public static bool TryVerify(byte[] secret, string? code, DateTimeOffset now, out long matchedStep)
    {
        matchedStep = 0;
        var normalized = Normalize(code);
        return normalized.Length == Digits
               && new OtpNet.Totp(secret, StepSeconds, OtpHashMode.Sha1, Digits).VerifyTotp(now.UtcDateTime, normalized, out matchedStep, Window);
    }

    /// <summary>Code for a given instant. Used by tests and never by the server to authenticate anyone.</summary>
    public static string Compute(byte[] secret, DateTimeOffset at)
        => new OtpNet.Totp(secret, StepSeconds, OtpHashMode.Sha1, Digits).ComputeTotp(at.UtcDateTime);

    public static string Normalize(string? code)
        => code is null ? string.Empty : new string(code.Where(char.IsAsciiDigit).Take(Digits + 1).ToArray());
}

public static class RecoveryCodes
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>80 bits from the system CSPRNG, shown as four groups of four base32 characters.</summary>
    public static string Generate()
    {
        var builder = new StringBuilder(19);
        for (var index = 0; index < 16; index++)
        {
            if (index > 0 && index % 4 == 0)
            {
                builder.Append('-');
            }

            builder.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
        }

        return builder.ToString();
    }

    public static string Normalize(string? code)
        => code is null ? string.Empty : new string(code.ToUpperInvariant().Where(Alphabet.Contains).Take(17).ToArray());

    /// <summary>The value is high-entropy random data, so a salted SHA-256 is an appropriate one-way storage form.</summary>
    public static byte[] Hash(Guid userId, string normalizedCode)
        => SHA256.HashData(Encoding.UTF8.GetBytes($"{userId:N}:{normalizedCode}"));
}

public sealed record Enrollment(string Base32Secret, string ProvisioningUri);

/// <summary>Authenticator enrollment, verification with replay protection, recovery codes and challenges.</summary>
public sealed class MfaService(
    IamDbContext db,
    IDataProtectionProvider protection,
    RevocationService revocation,
    AuditWriter audit,
    TimeProvider time,
    IOptions<MfaOptions> options)
{
    private readonly IDataProtector _protector = protection.CreateProtector("Halka.Iam.Mfa.Totp.v1");

    public Task<bool> IsEnabledAsync(Guid userId, CancellationToken cancellationToken)
        => db.UserMfa.AnyAsync(x => x.UserId == userId && x.Status == MfaStatus.Active, cancellationToken);

    /// <summary>Starts (or restarts) enrollment with a new secret. The secret is not valid for sign-in until confirmed.</summary>
    public async Task<Enrollment> BeginEnrollmentAsync(Guid userId, string account, CancellationToken cancellationToken)
    {
        var existing = await db.UserMfa.SingleOrDefaultAsync(x => x.UserId == userId, cancellationToken);
        if (existing is { Status: MfaStatus.Active })
        {
            throw new InvalidOperationException("An authenticator is already active. Remove it before enrolling a new one.");
        }

        var secret = TotpCodes.GenerateSecret();
        var now = time.GetUtcNow();
        if (existing is null)
        {
            db.UserMfa.Add(new UserMfa { UserId = userId, ProtectedSecret = _protector.Protect(secret), Status = MfaStatus.Pending, CreatedAt = now });
        }
        else
        {
            existing.ProtectedSecret = _protector.Protect(secret);
            existing.CreatedAt = now;
            existing.LastAcceptedStep = 0;
        }

        audit.Add("mfa.enrollment_started", AuditOutcome.Success, AuditActor.User, userId.ToString(), "user", userId.ToString());
        await db.SaveChangesAsync(cancellationToken);
        return new Enrollment(TotpCodes.ToBase32(secret), TotpCodes.ProvisioningUri(options.Value.Issuer, account, secret));
    }

    /// <summary>The pending enrollment, for display in the enrollment page only.</summary>
    public async Task<Enrollment?> GetPendingEnrollmentAsync(Guid userId, string account, CancellationToken cancellationToken)
    {
        var pending = await db.UserMfa.AsNoTracking().SingleOrDefaultAsync(x => x.UserId == userId && x.Status == MfaStatus.Pending, cancellationToken);
        if (pending is null)
        {
            return null;
        }

        var secret = _protector.Unprotect(pending.ProtectedSecret);
        return new Enrollment(TotpCodes.ToBase32(secret), TotpCodes.ProvisioningUri(options.Value.Issuer, account, secret));
    }

    /// <summary>
    /// Confirms a pending enrollment with a valid code and returns the first set of recovery codes (shown once).
    /// Other sessions of the user are ended because the account's sign-in requirements changed.
    /// </summary>
    public async Task<IReadOnlyList<string>?> ActivateAsync(Guid userId, string? code, Guid currentSessionId, CancellationToken cancellationToken)
    {
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        if (!await AcceptCodeAsync(userId, code, MfaStatus.Pending, cancellationToken))
        {
            await audit.WriteAsync("mfa.enrollment_confirm", AuditOutcome.Failure, AuditActor.User, userId.ToString(), "user", userId.ToString(), cancellationToken: cancellationToken);
            await scope.CommitAsync(cancellationToken);
            return null;
        }

        var now = time.GetUtcNow();
        var activated = await db.UserMfa
            .Where(x => x.UserId == userId && x.Status == MfaStatus.Pending)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.Status, MfaStatus.Active).SetProperty(x => x.ActivatedAt, now), cancellationToken);
        if (activated != 1)
        {
            return null;
        }

        var codes = await ReplaceRecoveryCodesAsync(userId, cancellationToken);
        await MarkSessionMfaAsync(currentSessionId, [Amr.Otp, Amr.Mfa], cancellationToken);
        await revocation.EndAllSessionsAsync(userId, SessionEndReason.MfaChanged, AuditActor.User, userId.ToString(), currentSessionId, cancellationToken);
        audit.Add("mfa.enabled", AuditOutcome.Success, AuditActor.User, userId.ToString(), "user", userId.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return codes;
    }

    /// <summary>Verifies a code of the active authenticator. Each time step is accepted at most once.</summary>
    public Task<bool> VerifyTotpAsync(Guid userId, string? code, CancellationToken cancellationToken)
        => AcceptCodeAsync(userId, code, MfaStatus.Active, cancellationToken);

    /// <summary>Redeems a recovery code. A conditional UPDATE guarantees a single success for concurrent attempts.</summary>
    public async Task<bool> RedeemRecoveryCodeAsync(Guid userId, string? code, CancellationToken cancellationToken)
    {
        var normalized = RecoveryCodes.Normalize(code);
        if (normalized.Length != 16)
        {
            return false;
        }

        var hash = RecoveryCodes.Hash(userId, normalized);
        var now = time.GetUtcNow();
        var redeemed = await db.RecoveryCodes
            .Where(x => x.UserId == userId && x.CodeHash == hash && x.UsedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.UsedAt, now), cancellationToken);
        await audit.WriteAsync("mfa.recovery_code", redeemed == 1 ? AuditOutcome.Success : AuditOutcome.Failure, AuditActor.User, userId.ToString(), "user", userId.ToString(), cancellationToken: cancellationToken);
        return redeemed == 1;
    }

    /// <summary>Issues a new set of recovery codes; every earlier code stops working.</summary>
    public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(Guid userId, CancellationToken cancellationToken)
    {
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var codes = await ReplaceRecoveryCodesAsync(userId, cancellationToken);
        audit.Add("mfa.recovery_codes_regenerated", AuditOutcome.Success, AuditActor.User, userId.ToString(), "user", userId.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return codes;
    }

    public Task<int> RemainingRecoveryCodesAsync(Guid userId, CancellationToken cancellationToken)
        => db.RecoveryCodes.CountAsync(x => x.UserId == userId && x.UsedAt == null, cancellationToken);

    /// <summary>
    /// Removes the authenticator and its recovery codes. Other sessions are ended (optionally all of them, for an
    /// administrator-assisted reset). The caller is responsible for requiring a recent second factor first.
    /// </summary>
    public async Task<bool> RemoveAsync(Guid userId, Guid? keepSessionId, string actorType, string? actorId, string reason, CancellationToken cancellationToken)
    {
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        var removed = await db.UserMfa.Where(x => x.UserId == userId).ExecuteDeleteAsync(cancellationToken);
        await db.RecoveryCodes.Where(x => x.UserId == userId).ExecuteDeleteAsync(cancellationToken);
        if (removed > 0)
        {
            await revocation.EndAllSessionsAsync(userId, SessionEndReason.MfaChanged, actorType, actorId, keepSessionId, cancellationToken);
            if (keepSessionId is { } current)
            {
                // The remaining session no longer has a second factor behind it.
                await db.UserSessions.Where(x => x.Id == current)
                    .ExecuteUpdateAsync(set => set.SetProperty(x => x.MfaVerifiedAt, (DateTimeOffset?)null).SetProperty(x => x.Amr, Amr.Password), cancellationToken);
            }

            audit.Add("mfa.disabled", AuditOutcome.Success, actorType, actorId, "user", userId.ToString(), reason);
            await db.SaveChangesAsync(cancellationToken);
        }

        await scope.CommitAsync(cancellationToken);
        return removed > 0;
    }

    public async Task<Guid> CreateChallengeAsync(Guid userId, string purpose, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var challenge = new MfaChallenge
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Purpose = purpose,
            CreatedAt = now,
            ExpiresAt = now + options.Value.ChallengeLifetime,
        };
        db.MfaChallenges.Add(challenge);
        await db.SaveChangesAsync(cancellationToken);
        return challenge.Id;
    }

    /// <summary>The user of a challenge that can still be attempted, or null when it is unknown, expired, used or exhausted.</summary>
    public async Task<Guid?> FindOpenChallengeAsync(Guid challengeId, string purpose, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var max = options.Value.MaxAttemptsPerChallenge;
        return await db.MfaChallenges.AsNoTracking()
            .Where(x => x.Id == challengeId && x.Purpose == purpose && x.ConsumedAt == null && x.ExpiresAt > now && x.Attempts < max)
            .Select(x => (Guid?)x.UserId)
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <summary>Counts one attempt. Returns false when the challenge has no attempts left or is no longer open.</summary>
    public async Task<bool> TryCountAttemptAsync(Guid challengeId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var max = options.Value.MaxAttemptsPerChallenge;
        var counted = await db.MfaChallenges
            .Where(x => x.Id == challengeId && x.ConsumedAt == null && x.ExpiresAt > now && x.Attempts < max)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.Attempts, x => x.Attempts + 1), cancellationToken);
        return counted == 1;
    }

    /// <summary>Completes a challenge exactly once.</summary>
    public async Task<bool> TryConsumeChallengeAsync(Guid challengeId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var consumed = await db.MfaChallenges
            .Where(x => x.Id == challengeId && x.ConsumedAt == null && x.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.ConsumedAt, now), cancellationToken);
        return consumed == 1;
    }

    /// <summary>Records a successful second factor on a session (step-up or enrollment confirmation).</summary>
    public async Task MarkSessionMfaAsync(Guid sessionId, IReadOnlyCollection<string> methods, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var current = await db.UserSessions.AsNoTracking().Where(x => x.Id == sessionId).Select(x => x.Amr).SingleOrDefaultAsync(cancellationToken);
        if (current is null)
        {
            return;
        }

        var amr = Amr.Join(Amr.Split(current).Concat(methods));
        await db.UserSessions.Where(x => x.Id == sessionId && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.MfaVerifiedAt, now).SetProperty(x => x.Amr, amr), cancellationToken);
    }

    public Task MarkSessionPasswordAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        return db.UserSessions.Where(x => x.Id == sessionId && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.PasswordVerifiedAt, now), cancellationToken);
    }

    /// <summary>
    /// Verifies the code and advances the last accepted time step in one conditional UPDATE. Two requests with the
    /// same valid code race on that row: the first moves the step forward, the second no longer matches the
    /// condition and is rejected. Codes of earlier steps are rejected for the same reason.
    /// </summary>
    private async Task<bool> AcceptCodeAsync(Guid userId, string? code, string status, CancellationToken cancellationToken)
    {
        var row = await db.UserMfa.AsNoTracking()
            .Where(x => x.UserId == userId && x.Status == status)
            .Select(x => new { x.ProtectedSecret })
            .SingleOrDefaultAsync(cancellationToken);
        if (row is null)
        {
            return false;
        }

        var secret = _protector.Unprotect(row.ProtectedSecret);
        try
        {
            if (!TotpCodes.TryVerify(secret, code, time.GetUtcNow(), out var step))
            {
                return false;
            }

            var accepted = await db.UserMfa
                .Where(x => x.UserId == userId && x.Status == status && x.LastAcceptedStep < step)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.LastAcceptedStep, step), cancellationToken);
            return accepted == 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private async Task<IReadOnlyList<string>> ReplaceRecoveryCodesAsync(Guid userId, CancellationToken cancellationToken)
    {
        await db.RecoveryCodes.Where(x => x.UserId == userId).ExecuteDeleteAsync(cancellationToken);
        var batch = Guid.NewGuid();
        var now = time.GetUtcNow();
        var codes = Enumerable.Range(0, options.Value.RecoveryCodeCount).Select(_ => RecoveryCodes.Generate()).Distinct(StringComparer.Ordinal).ToList();
        foreach (var code in codes)
        {
            db.RecoveryCodes.Add(new RecoveryCode
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                CodeHash = RecoveryCodes.Hash(userId, RecoveryCodes.Normalize(code)),
                BatchId = batch,
                CreatedAt = now,
            });
        }

        await db.SaveChangesAsync(cancellationToken);
        return codes;
    }
}
