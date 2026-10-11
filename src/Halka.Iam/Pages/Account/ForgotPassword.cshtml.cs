using System.ComponentModel.DataAnnotations;
using Halka.Iam.Identity;
using Halka.Iam.Ops;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Halka.Iam.Pages.Account;

[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.Recovery)]
public sealed class ForgotPasswordModel(AccountService accounts) : PageModel
{
    [BindProperty, Required(ErrorMessage = "Enter an e-mail address."), EmailAddress(ErrorMessage = "Enter a valid e-mail address."), StringLength(254)]
    public string Email { get; set; } = string.Empty;

    public bool Sent { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        await accounts.RequestPasswordResetAsync(Email, cancellationToken);
        Sent = true;
        return Page();
    }
}
