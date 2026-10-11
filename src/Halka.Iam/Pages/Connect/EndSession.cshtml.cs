using Halka.Iam.Sessions;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace Halka.Iam.Pages.Connect;

/// <summary>
/// RP-initiated logout (pass-through). OpenIddict has validated the request, in particular that
/// post_logout_redirect_uri is registered for the client identified by client_id or id_token_hint; an unregistered
/// target never reaches this page. Ending the session needs an explicit, anti-forgery protected confirmation, so
/// another site cannot sign the user out with a crafted link.
/// </summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken] // Relying parties reach this endpoint by navigation; the confirmation POST is validated below.
public sealed class EndSessionModel(SessionSignIn signIn, IAntiforgery antiforgery) : PageModel
{
    public const string DecisionField = "logout_decision";
    public const string Confirm = "confirm";
    private const string Scheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    public IReadOnlyList<KeyValuePair<string, string?>> Parameters { get; private set; } = [];

    public Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) => HandleAsync(cancellationToken);

    public Task<IActionResult> OnPostAsync(CancellationToken cancellationToken) => HandleAsync(cancellationToken);

    private async Task<IActionResult> HandleAsync(CancellationToken cancellationToken)
    {
        var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Nothing to confirm when this browser has no central session: complete the protocol response directly.
        if (HttpContext.GetCurrentSession() is null)
        {
            return Complete();
        }

        var decision = Request.HasFormContentType ? Request.Form[DecisionField].ToString() : string.Empty;
        if (decision != Confirm)
        {
            Parameters = (from parameter in request.GetParameters()
                          where parameter.Key is not (DecisionField or "__RequestVerificationToken")
                          let value = (string?)parameter.Value
                          where value is not null
                          select new KeyValuePair<string, string?>(parameter.Key, value)).ToList();
            return Page();
        }

        if (!await antiforgery.IsRequestValidAsync(HttpContext))
        {
            return BadRequest();
        }

        // Ends the central session and revokes its grants; relying parties notice on their next state check.
        await signIn.SignOutAsync(HttpContext, SessionEndReason.Logout, cancellationToken);
        Response.Headers["Clear-Site-Data"] = "\"cache\"";
        return Complete();
    }

    /// <summary>Lets OpenIddict redirect to the validated post_logout_redirect_uri (with state), or to the sign-in page.</summary>
    private SignOutResult Complete()
        => SignOut(new AuthenticationProperties { RedirectUri = "/account/login?notice=signed-out" }, Scheme);
}
