using Halka.Iam.Data;
using Halka.Iam.Mfa;
using Halka.Iam.Ops;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Halka.Iam.Pages.Account;

/// <summary>
/// Second step of sign-in. Until this step succeeds the browser only holds a pending-challenge cookie, which is
/// not a session: protected pages and the authorization endpoint still treat the browser as signed out.
/// </summary>
public abstract class SecondFactorModel(
    MfaService mfa,
    PendingChallengeCookie pending,
    UserManager<ApplicationUser> users,
    SessionSignIn signIn,
    AccountAttemptLimiter limiter) : PageModel
{
    private const string Expired = "/account/login?notice=challenge-expired";

    [BindProperty]
    public string? Code { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; protected set; }

    protected MfaService Mfa { get; } = mfa;

    protected abstract string InvalidMessage { get; }

    /// <summary>Methods to record on the session when this factor succeeds (RFC 8176 values).</summary>
    protected abstract IReadOnlyCollection<string> Methods { get; }

    protected abstract Task<bool> VerifyAsync(Guid userId, CancellationToken cancellationToken);

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
        => await OpenChallengeAsync(cancellationToken) is null ? RestartAsync() : Page();

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (await OpenChallengeAsync(cancellationToken) is not { } open)
        {
            return RestartAsync();
        }

        var (challengeId, userId) = open;

        // Attempts are bounded twice: per challenge (in the database) and per account across challenges.
        if (!await Mfa.TryCountAttemptAsync(challengeId, cancellationToken) || !limiter.TryAcquire("second-factor", userId.ToString()))
        {
            return RestartAsync();
        }

        if (!await VerifyAsync(userId, cancellationToken))
        {
            ErrorMessage = InvalidMessage;
            return Page();
        }

        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null || user.IsDisabled || !await Mfa.TryConsumeChallengeAsync(challengeId, cancellationToken))
        {
            return RestartAsync();
        }

        pending.Clear(HttpContext);
        await signIn.SignInAsync(HttpContext, user, [Amr.Password, .. Methods], cancellationToken);
        return LocalRedirect(ReturnUrls.Safe(Url, ReturnUrl));
    }

    private async Task<(Guid ChallengeId, Guid UserId)?> OpenChallengeAsync(CancellationToken cancellationToken)
    {
        if (pending.Read(HttpContext) is not { } challengeId)
        {
            return null;
        }

        return await Mfa.FindOpenChallengeAsync(challengeId, MfaChallengePurpose.Login, cancellationToken) is { } userId ? (challengeId, userId) : null;
    }

    private IActionResult RestartAsync()
    {
        pending.Clear(HttpContext);
        var target = string.IsNullOrEmpty(ReturnUrl) || !Url.IsLocalUrl(ReturnUrl) ? Expired : $"{Expired}&returnUrl={Uri.EscapeDataString(ReturnUrl)}";
        return LocalRedirect(target);
    }
}

[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.Mfa)]
public sealed class MfaModel(MfaService mfa, PendingChallengeCookie pending, UserManager<ApplicationUser> users, SessionSignIn signIn, AccountAttemptLimiter limiter)
    : SecondFactorModel(mfa, pending, users, signIn, limiter)
{
    protected override string InvalidMessage => "The code is not valid. Codes change every 30 seconds and each code can be used once.";

    protected override IReadOnlyCollection<string> Methods => [Amr.Otp, Amr.Mfa];

    protected override Task<bool> VerifyAsync(Guid userId, CancellationToken cancellationToken) => Mfa.VerifyTotpAsync(userId, Code, cancellationToken);
}

[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.Mfa)]
public sealed class RecoveryModel(MfaService mfa, PendingChallengeCookie pending, UserManager<ApplicationUser> users, SessionSignIn signIn, AccountAttemptLimiter limiter)
    : SecondFactorModel(mfa, pending, users, signIn, limiter)
{
    protected override string InvalidMessage => "The recovery code is not valid or was already used.";

    protected override IReadOnlyCollection<string> Methods => [Amr.Mfa];

    protected override Task<bool> VerifyAsync(Guid userId, CancellationToken cancellationToken) => Mfa.RedeemRecoveryCodeAsync(userId, Code, cancellationToken);
}
