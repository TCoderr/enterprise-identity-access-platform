using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Ops;
using Microsoft.AspNetCore.Identity;

namespace Halka.Iam.Identity;

public enum PasswordCheckOutcome
{
    /// <summary>Wrong credentials, unknown account, locked out or disabled. Callers show one generic message.</summary>
    Rejected,
    Throttled,
    EmailNotConfirmed,
    Verified,
}

public sealed record PasswordCheckResult(PasswordCheckOutcome Outcome, ApplicationUser? User = null);

/// <summary>
/// Primary-factor verification. Unknown accounts, wrong passwords, locked-out and disabled accounts all produce the
/// same <see cref="PasswordCheckOutcome.Rejected"/> outcome so the response cannot be used to enumerate accounts.
/// </summary>
public sealed class LoginService(
    UserManager<ApplicationUser> users,
    IPasswordHasher<ApplicationUser> hasher,
    AccountAttemptLimiter limiter,
    AuditWriter audit,
    IamMetrics metrics)
{
    // A real PBKDF2 hash that is verified for unknown accounts, so both paths spend comparable time.
    private static readonly Lazy<string> DecoyHash = new(() =>
        new PasswordHasher<ApplicationUser>().HashPassword(new ApplicationUser(), Guid.NewGuid().ToString("N")));

    public async Task<PasswordCheckResult> CheckPasswordAsync(
        string email,
        string password,
        string remoteAddress,
        CancellationToken cancellationToken)
    {
        var normalized = users.NormalizeEmail(email) ?? string.Empty;
        if (!limiter.TryAcquire(remoteAddress, normalized))
        {
            metrics.SignIn("password", "throttled");
            return new PasswordCheckResult(PasswordCheckOutcome.Throttled);
        }

        var result = await CheckAsync(email, password, cancellationToken);
        metrics.SignIn("password", result.Outcome == PasswordCheckOutcome.Verified ? "success" : "rejected");
        return result;
    }

    private async Task<PasswordCheckResult> CheckAsync(string email, string password, CancellationToken cancellationToken)
    {

        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            hasher.VerifyHashedPassword(new ApplicationUser(), DecoyHash.Value, password);
            await audit.WriteAsync("login.password", AuditOutcome.Failure, AuditActor.Anonymous, null, reason: "unknown_account", cancellationToken: cancellationToken);
            return new PasswordCheckResult(PasswordCheckOutcome.Rejected);
        }

        if (await users.IsLockedOutAsync(user))
        {
            hasher.VerifyHashedPassword(user, DecoyHash.Value, password);
            await audit.WriteAsync("login.password", AuditOutcome.Denied, AuditActor.User, user.Id.ToString(), reason: "locked_out", cancellationToken: cancellationToken);
            return new PasswordCheckResult(PasswordCheckOutcome.Rejected);
        }

        if (!await users.CheckPasswordAsync(user, password))
        {
            await users.AccessFailedAsync(user);
            await audit.WriteAsync("login.password", AuditOutcome.Failure, AuditActor.User, user.Id.ToString(), reason: "wrong_password", cancellationToken: cancellationToken);
            return new PasswordCheckResult(PasswordCheckOutcome.Rejected);
        }

        if (user.IsDisabled)
        {
            await audit.WriteAsync("login.password", AuditOutcome.Denied, AuditActor.User, user.Id.ToString(), reason: "account_disabled", cancellationToken: cancellationToken);
            return new PasswordCheckResult(PasswordCheckOutcome.Rejected);
        }

        if (!user.EmailConfirmed)
        {
            await audit.WriteAsync("login.password", AuditOutcome.Denied, AuditActor.User, user.Id.ToString(), reason: "email_not_confirmed", cancellationToken: cancellationToken);
            return new PasswordCheckResult(PasswordCheckOutcome.EmailNotConfirmed);
        }

        await users.ResetAccessFailedCountAsync(user);
        return new PasswordCheckResult(PasswordCheckOutcome.Verified, user);
    }
}
