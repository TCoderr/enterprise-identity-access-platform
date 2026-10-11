using System.ComponentModel.DataAnnotations;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Ops;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Halka.Iam.Pages.Account;

[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.Recovery)]
public sealed class ResetPasswordModel(AccountService accounts, OneTimeTokenService tokens, RevocationService revocation) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    [BindProperty, Required(ErrorMessage = "Enter a new password."), StringLength(256, ErrorMessage = "The password can be at most 256 characters.")]
    public string NewPassword { get; set; } = string.Empty;

    public bool TokenInvalid { get; private set; }

    public IReadOnlyList<string> Errors { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        ModelState.Clear();
        TokenInvalid = !await tokens.IsValidAsync(Token, OneTimeTokenPurpose.ResetPassword, cancellationToken);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            Errors = ModelState.Values.SelectMany(entry => entry.Errors).Select(error => error.ErrorMessage).Distinct().ToList();
            return Page();
        }

        var result = await accounts.ResetPasswordAsync(Token, NewPassword, revocation, cancellationToken);
        if (result.Succeeded)
        {
            await HttpContext.SignOutIfPresentAsync();
            return LocalRedirect("/account/login?notice=password-reset");
        }

        TokenInvalid = result.TokenInvalid;
        Errors = result.Errors;
        return Page();
    }
}
