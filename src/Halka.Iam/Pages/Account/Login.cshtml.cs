using System.ComponentModel.DataAnnotations;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mfa;
using Halka.Iam.Ops;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Halka.Iam.Pages.Account;

[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.LoginAddress)]
public sealed class LoginModel(
    LoginService login,
    SessionSignIn signIn,
    MfaService mfa,
    PendingChallengeCookie pending,
    TimeProvider time,
    Microsoft.Extensions.Options.IOptions<MfaOptions> mfaOptions) : PageModel
{
    public const string GenericError = "The e-mail address or password is not correct, or the account cannot sign in right now.";

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>
    /// Set by the authorization endpoint when an application demands a fresh sign-in (prompt=login, max_age). The
    /// form is then shown even though a session exists. It grants nothing by itself: the authorization endpoint
    /// verifies independently that a new session was created.
    /// </summary>
    [BindProperty(SupportsGet = true)]
    public bool Reauth { get; set; }

    public string? ErrorMessage { get; private set; }

    public string? Notice { get; private set; }

    public IActionResult OnGet(string? notice)
    {
        if (HttpContext.GetCurrentSession() is not null && !Reauth)
        {
            return LocalRedirect(ReturnUrls.Safe(Url, ReturnUrl));
        }

        Notice = notice switch
        {
            _ when Reauth => "The application asked you to sign in again to continue.",
            "signed-out" => "You have signed out of Halka ID.",
            "confirmed" => "Your e-mail address is confirmed. You can sign in now.",
            "password-reset" => "Your password was changed. Sign in with the new password.",
            "challenge-expired" => "The verification step expired or had too many attempts. Sign in again.",
            _ => null,
        };
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            ErrorMessage = GenericError;
            return Page();
        }

        var result = await login.CheckPasswordAsync(Input.Email, Input.Password, RateLimitPolicies.Address(HttpContext), cancellationToken);
        switch (result.Outcome)
        {
            case PasswordCheckOutcome.Verified when await mfa.IsEnabledAsync(result.User!.Id, cancellationToken):
                // The password is only the first step. No session exists until the second factor is verified.
                var challenge = await mfa.CreateChallengeAsync(result.User!.Id, MfaChallengePurpose.Login, cancellationToken);
                pending.Set(HttpContext, challenge, time.GetUtcNow() + mfaOptions.Value.ChallengeLifetime);
                return RedirectToPage("/Account/Mfa", new { returnUrl = ReturnUrls.Safe(Url, ReturnUrl) });

            case PasswordCheckOutcome.Verified:
                await signIn.SignInAsync(HttpContext, result.User!, [Amr.Password], cancellationToken);
                return LocalRedirect(ReturnUrls.Safe(Url, ReturnUrl));

            case PasswordCheckOutcome.EmailNotConfirmed:
                ErrorMessage = "Confirm your e-mail address before signing in. Use the link in the confirmation message.";
                return Page();

            case PasswordCheckOutcome.Throttled:
                Response.StatusCode = StatusCodes.Status429TooManyRequests;
                ErrorMessage = "Too many sign-in attempts. Wait a minute and try again.";
                return Page();

            default:
                ErrorMessage = GenericError;
                return Page();
        }
    }

    public sealed class InputModel
    {
        [Required, EmailAddress, StringLength(254)]
        public string Email { get; set; } = string.Empty;

        [Required, StringLength(256)]
        public string Password { get; set; } = string.Empty;
    }
}

public static class ReturnUrls
{
    public const string Default = "/manage";

    /// <summary>
    /// Only same-origin relative paths are accepted. Anything else (absolute URLs, protocol-relative "//host",
    /// backslash variants) falls back to the account page, so the login flow cannot be used as an open redirect.
    /// </summary>
    public static string Safe(IUrlHelper url, string? returnUrl)
        => !string.IsNullOrEmpty(returnUrl) && url.IsLocalUrl(returnUrl) ? returnUrl : Default;
}
