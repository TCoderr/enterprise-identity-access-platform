using System.Security.Cryptography;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Mfa;

/// <summary>
/// Marks a page or a page handler as sensitive: it only runs when the session re-authenticated recently
/// (a second factor for accounts with MFA, the password otherwise). A valid session cookie alone is not enough.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class RequireStepUpAttribute : Attribute;

/// <summary>
/// Enforces step-up and the administrator MFA rule for Razor Pages. The decision is made on the server from the
/// session row loaded for this request; nothing in the cookie or the request can assert freshness.
/// </summary>
public sealed class StepUpPageFilter(TimeProvider time, IOptions<CentralSessionOptions> options) : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var http = context.HttpContext;
        var session = http.GetCurrentSession();
        if (session is not null)
        {
            var isAdminPage = context.ActionDescriptor.ViewEnginePath.StartsWith("/Admin", StringComparison.OrdinalIgnoreCase);
            if (isAdminPage && !session.MfaEnabled)
            {
                // Administrators cannot use the administration area without an enrolled second factor.
                context.Result = new LocalRedirectResult("/manage/mfa?required=admin");
                return;
            }

            var sensitive = context.HandlerMethod?.MethodInfo.IsDefined(typeof(RequireStepUpAttribute), inherit: true) == true
                            || context.HandlerInstance.GetType().IsDefined(typeof(RequireStepUpAttribute), inherit: true);
            var needsSecondFactor = isAdminPage && !session.HasMfa;
            if (needsSecondFactor || (sensitive && !session.IsStepUpFresh(time.GetUtcNow(), options.Value.StepUpWindow)))
            {
                // After re-authentication the browser returns to the page (GET); a refused POST is not replayed.
                var path = (http.Request.PathBase + http.Request.Path).ToString();
                var returnUrl = HttpMethods.IsGet(http.Request.Method) ? path + http.Request.QueryString : path;
                context.Result = new LocalRedirectResult($"/account/step-up?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return;
            }
        }

        await next();
    }
}

/// <summary>
/// Cookie that carries the identifier of a pending second-factor challenge between the password page and the code
/// page. It is not an authentication cookie: no scheme reads it and it grants access to nothing.
/// </summary>
public sealed class PendingChallengeCookie(IDataProtectionProvider protection)
{
    public const string CookieName = "__Host-halka-mfa";
    private readonly IDataProtector _protector = protection.CreateProtector("Halka.Iam.Mfa.PendingChallenge.v1");

    public void Set(HttpContext http, Guid challengeId, DateTimeOffset expires)
        => http.Response.Cookies.Append(CookieName, _protector.Protect(challengeId.ToString("N")), Options(expires));

    public Guid? Read(HttpContext http)
    {
        if (!http.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            return Guid.TryParseExact(_protector.Unprotect(value), "N", out var id) ? id : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    public void Clear(HttpContext http) => http.Response.Cookies.Delete(CookieName, Options(null));

    private static CookieOptions Options(DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
        Expires = expires,
    };
}
