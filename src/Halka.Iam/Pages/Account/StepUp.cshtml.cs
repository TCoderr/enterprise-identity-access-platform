using Halka.Iam.Audit;
using Halka.Iam.Identity;
using Halka.Iam.Mfa;
using Halka.Iam.Ops;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Pages.Account;

/// <summary>
/// Re-authentication for sensitive actions. Accounts with an authenticator must present a second factor; the
/// password alone is only accepted for accounts that have none. Success is recorded on the session row.
/// </summary>
[Authorize]
[EnableRateLimiting(RateLimitPolicies.Mfa)]
public sealed class StepUpModel(
    MfaService mfa,
    LoginService login,
    AccountAttemptLimiter limiter,
    AuditWriter audit,
    IOptions<CentralSessionOptions> options) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public bool UsesSecondFactor { get; private set; }

    public string? ErrorMessage { get; private set; }

    public int WindowMinutes => (int)options.Value.StepUpWindow.TotalMinutes;

    public void OnGet() => UsesSecondFactor = HttpContext.RequireCurrentSession().MfaEnabled;

    public Task<IActionResult> OnPostTotpAsync(string? code, CancellationToken cancellationToken)
        => SecondFactorAsync(session => mfa.VerifyTotpAsync(session.UserId, code, cancellationToken), [Amr.Otp, Amr.Mfa], "The code is not valid. Each code can be used once.", cancellationToken);

    public Task<IActionResult> OnPostRecoveryAsync(string? code, CancellationToken cancellationToken)
        => SecondFactorAsync(session => mfa.RedeemRecoveryCodeAsync(session.UserId, code, cancellationToken), [Amr.Mfa], "The recovery code is not valid or was already used.", cancellationToken);

    public async Task<IActionResult> OnPostPasswordAsync(string? password, CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        UsesSecondFactor = session.MfaEnabled;
        if (session.MfaEnabled)
        {
            // An account with a second factor cannot step up with the password.
            ErrorMessage = "Use your authenticator app to confirm.";
            return Page();
        }

        var result = await login.CheckPasswordAsync(session.Email, password ?? string.Empty, RateLimitPolicies.Address(HttpContext), cancellationToken);
        if (result.Outcome != PasswordCheckOutcome.Verified)
        {
            ErrorMessage = result.Outcome == PasswordCheckOutcome.Throttled ? "Too many attempts. Wait a minute and try again." : "The password is not correct.";
            return Page();
        }

        await mfa.MarkSessionPasswordAsync(session.Id, cancellationToken);
        await audit.WriteAsync("session.step_up", AuditOutcome.Success, AuditActor.User, session.UserId.ToString(), "session", session.Id.ToString(), "password", cancellationToken);
        return LocalRedirect(ReturnUrls.Safe(Url, ReturnUrl));
    }

    private async Task<IActionResult> SecondFactorAsync(Func<CurrentSession, Task<bool>> verify, IReadOnlyCollection<string> methods, string invalid, CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        UsesSecondFactor = session.MfaEnabled;
        if (!session.MfaEnabled)
        {
            ErrorMessage = "This account has no authenticator. Confirm with your password.";
            return Page();
        }

        if (!limiter.TryAcquire("second-factor", session.UserId.ToString()))
        {
            Response.StatusCode = StatusCodes.Status429TooManyRequests;
            ErrorMessage = "Too many attempts. Wait a minute and try again.";
            return Page();
        }

        if (!await verify(session))
        {
            await audit.WriteAsync("session.step_up", AuditOutcome.Failure, AuditActor.User, session.UserId.ToString(), "session", session.Id.ToString(), cancellationToken: cancellationToken);
            ErrorMessage = invalid;
            return Page();
        }

        await mfa.MarkSessionMfaAsync(session.Id, methods, cancellationToken);
        await audit.WriteAsync("session.step_up", AuditOutcome.Success, AuditActor.User, session.UserId.ToString(), "session", session.Id.ToString(), string.Join(' ', methods), cancellationToken);
        return LocalRedirect(ReturnUrls.Safe(Url, ReturnUrl));
    }
}
