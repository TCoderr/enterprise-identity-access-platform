using Halka.Iam.Identity;
using Halka.Iam.Ops;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Halka.Iam.Pages.Account;

/// <summary>
/// The link only renders a form; the token is consumed by the POST. Link scanners and browser prefetch therefore
/// cannot burn the single-use token.
/// </summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.Recovery)]
public sealed class ConfirmEmailModel(AccountService accounts) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    public bool Failed { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (await accounts.ConfirmEmailAsync(Token, cancellationToken))
        {
            return LocalRedirect("/account/login?notice=confirmed");
        }

        Failed = true;
        return Page();
    }
}
