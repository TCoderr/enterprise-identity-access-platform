using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Halka.Iam.Pages.Account;

/// <summary>Local sign-out of the central session. A POST with an anti-forgery token is required, so a cross-site request cannot log the user out.</summary>
[AllowAnonymous]
public sealed class LogoutModel(SessionSignIn signIn) : PageModel
{
    public IActionResult OnGet()
        => HttpContext.GetCurrentSession() is null ? LocalRedirect("/account/login") : Page();

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        await signIn.SignOutAsync(HttpContext, SessionEndReason.Logout, cancellationToken);
        Response.Headers["Clear-Site-Data"] = "\"cache\"";
        return LocalRedirect("/account/login?notice=signed-out");
    }
}
