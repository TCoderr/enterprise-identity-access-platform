using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Halka.DemoClient.Pages;

[AllowAnonymous]
public sealed class IndexModel : PageModel
{
    public void OnGet()
    {
    }
}

/// <summary>Starts the sign-in by browser navigation (never by fetch): the response is a redirect to the identity provider.</summary>
[AllowAnonymous]
public sealed class LoginModel : PageModel
{
    public IActionResult OnGet(string? returnUrl)
        => Challenge(new AuthenticationProperties { RedirectUri = Local(returnUrl) }, DemoClientHost.OidcScheme);

    /// <summary>Only same-origin paths are accepted as a return target.</summary>
    internal static string Local(string? returnUrl, string fallback = "/workspace")
        => !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) && !returnUrl.StartsWith("/\\", StringComparison.Ordinal)
            ? returnUrl
            : fallback;
}

[AllowAnonymous]
public sealed class SignedOutModel(IOptions<DemoClientOptions> options) : PageModel
{
    public string Message { get; private set; } = string.Empty;

    public void OnGet(string? scope)
    {
        Response.Headers["Clear-Site-Data"] = "\"cache\"";
        Message = scope == "global"
            ? "You signed out of Halka ID. Every application that was opened from that session, including this one, has lost access."
            : $"You signed out of {options.Value.Name} only. Your Halka ID session is still active, so signing in again will not ask for your credentials.";
    }
}

[AllowAnonymous]
public sealed class SigninProblemModel : PageModel
{
    public string Message { get; private set; } = string.Empty;

    public void OnGet(string? reason)
        => Message = reason == "denied"
            ? "You did not allow this application to access your account, so you were not signed in."
            : "Sign-in could not be completed. The response from the identity provider was not accepted.";
}

[AllowAnonymous]
[IgnoreAntiforgeryToken]
public sealed class ProblemModel : PageModel
{
    public string Heading { get; private set; } = "Something went wrong";

    public string Message { get; private set; } = "The request could not be completed.";

    public void OnGet(int? status) => Describe(status);

    public void OnPost(int? status) => Describe(status);

    private void Describe(int? status)
    {
        (Heading, Message) = status switch
        {
            400 => ("The request was not valid", "The form may have expired. Go back, reload the page and try again."),
            404 => ("Page not found", "The page does not exist."),
            _ => (Heading, Message),
        };
    }
}

public sealed class LogoutModel(AppSessionStore store, SessionGuard guard, OpClient op) : PageModel
{
    public IActionResult OnGet() => LocalRedirect("/session");

    /// <summary>
    /// Local logout: ends this application's session and revokes this application's own tokens at the identity
    /// provider. The central Halka ID session and the other application are not affected.
    /// </summary>
    public async Task<IActionResult> OnPostLocalAsync(CancellationToken cancellationToken)
    {
        if (DemoClientHost.SessionId(User) is { } id)
        {
            if (await store.FindAsync(id, cancellationToken) is { } session)
            {
                if (session.Tokens.RefreshToken is { Length: > 0 } refreshToken)
                {
                    await op.TryRevokeAsync(refreshToken, "refresh_token", cancellationToken);
                }

                await op.TryRevokeAsync(session.Tokens.AccessToken, "access_token", cancellationToken);
            }

            await guard.EndAsync(id, cancellationToken);
        }

        await HttpContext.SignOutAsync(DemoClientHost.CookieScheme);
        return LocalRedirect("/signed-out?scope=local");
    }

    /// <summary>
    /// Global logout (RP-initiated): ends this application's session, then sends the browser to the identity
    /// provider's end-session endpoint, which asks for confirmation and ends the central session.
    /// </summary>
    public async Task<IActionResult> OnPostGlobalAsync(CancellationToken cancellationToken)
    {
        var properties = new AuthenticationProperties { RedirectUri = "/signed-out?scope=global" };
        if (DemoClientHost.SessionId(User) is { } id)
        {
            if (await store.FindAsync(id, cancellationToken) is { Tokens.IdToken: { Length: > 0 } idToken })
            {
                properties.Items[DemoClientHost.IdTokenHint] = idToken;
            }

            await guard.EndAsync(id, cancellationToken);
        }

        return SignOut(properties, DemoClientHost.CookieScheme, DemoClientHost.OidcScheme);
    }
}

public sealed class SessionModel(SessionGuard guard, IOptions<DemoClientOptions> options, TimeProvider time, IWebHostEnvironment environment) : PageModel
{
    public string Subject { get; private set; } = string.Empty;

    public IReadOnlyList<string> Scopes { get; private set; } = [];

    public IReadOnlyList<string> Methods { get; private set; } = [];

    public DateTimeOffset? AuthTime { get; private set; }

    public DateTimeOffset AccessTokenExpiresAt { get; private set; }

    public bool HasRefreshToken { get; private set; }

    public bool ShowTechnicalPanel => environment.IsDevelopment();

    public string Issuer => options.Value.Authority;

    [TempData]
    public string? Notice { get; set; }

    public IActionResult OnGet()
    {
        var session = DemoClientHost.CurrentSession(HttpContext);
        if (session is null)
        {
            return Challenge(DemoClientHost.OidcScheme);
        }

        Load(session);
        return Page();
    }

    /// <summary>Forces a token refresh through the same single-flight path the automatic refresh uses.</summary>
    public async Task<IActionResult> OnPostRefreshAsync(CancellationToken cancellationToken)
    {
        if (DemoClientHost.SessionId(User) is not { } id || await guard.EnsureActiveAsync(id, forceRefresh: true, cancellationToken) is not { } session)
        {
            await HttpContext.SignOutAsync(DemoClientHost.CookieScheme);
            return LocalRedirect("/?ended=1");
        }

        Notice = $"Tokens were refreshed. The new access token expires at {session.Tokens.ExpiresAt:HH:mm:ss} UTC.";
        return RedirectToPage();
    }

    /// <summary>Asks the identity provider for a fresh sign-in (prompt=login) and verifies afterwards that it happened.</summary>
    public IActionResult OnPostFresh()
    {
        var properties = new OpenIdConnectChallengeProperties { RedirectUri = "/session", Prompt = "login" };
        properties.Items[DemoClientHost.FreshRequestedAt] = time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        return Challenge(properties, DemoClientHost.OidcScheme);
    }

    private void Load(StoredSession session)
    {
        Subject = User.FindFirst("sub")?.Value ?? string.Empty;
        Scopes = session.Tokens.Scopes;
        Methods = User.FindAll("amr").Select(claim => claim.Value).ToList();
        AuthTime = long.TryParse(User.FindFirst("auth_time")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
        AccessTokenExpiresAt = session.Tokens.ExpiresAt;
        HasRefreshToken = !string.IsNullOrEmpty(session.Tokens.RefreshToken);
    }
}

public sealed class WorkspaceModel(WorkspaceApiClient api, IOptions<DemoClientOptions> options) : PageModel
{
    public bool CanWrite => options.Value.CanWrite;

    public ApiCallResult? Result { get; private set; }

    [BindProperty]
    public string? NoteText { get; set; }

    public IActionResult OnGet()
        => DemoClientHost.CurrentSession(HttpContext) is null ? Challenge(DemoClientHost.OidcScheme) : Page();

    public Task<IActionResult> OnPostLoadAsync(CancellationToken cancellationToken)
        => CallAsync((token, ct) => api.ListAsync(token, ct), cancellationToken);

    public Task<IActionResult> OnPostSensitiveAsync(CancellationToken cancellationToken)
        => CallAsync((token, ct) => api.ListSensitiveAsync(token, ct), cancellationToken);

    public Task<IActionResult> OnPostAddAsync(CancellationToken cancellationToken)
        => CallAsync((token, ct) => api.AddAsync(token, (NoteText ?? string.Empty).Trim(), ct), cancellationToken);

    private async Task<IActionResult> CallAsync(Func<string, CancellationToken, Task<ApiCallResult>> call, CancellationToken cancellationToken)
    {
        var session = DemoClientHost.CurrentSession(HttpContext);
        if (session is null)
        {
            return Challenge(DemoClientHost.OidcScheme);
        }

        Result = await call(session.Tokens.AccessToken, cancellationToken);
        return Page();
    }
}
