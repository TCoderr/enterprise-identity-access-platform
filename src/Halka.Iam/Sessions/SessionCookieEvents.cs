using Halka.Iam.Audit;
using Halka.Iam.Revocation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace Halka.Iam.Sessions;

/// <summary>
/// Validates the session cookie against the database on every request. A cookie that was captured before logout,
/// revocation, user disable or expiry is rejected here even though its signature and lifetime are still valid.
/// </summary>
public sealed class SessionCookieEvents(SessionService sessions, RevocationService revocation) : CookieAuthenticationEvents
{
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var cancellationToken = context.HttpContext.RequestAborted;
        if (!SessionPrincipal.TryRead(context.Principal, out var userId, out var sessionId))
        {
            await RejectAsync(context);
            return;
        }

        var lookup = await sessions.LoadAsync(sessionId, userId, cancellationToken);
        if (lookup.Session is null)
        {
            if (lookup.ExpiredReason is not null)
            {
                await revocation.EndSessionAsync(sessionId, lookup.ExpiredReason, AuditActor.System, null, cancellationToken);
            }

            await RejectAsync(context);
            return;
        }

        context.HttpContext.SetCurrentSession(lookup.Session);
        context.ReplacePrincipal(SessionPrincipal.ForRequest(lookup.Session));
    }

    public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    {
        if (IsApiRequest(context.Request))
        {
            return WriteProblemAsync(context.HttpContext, StatusCodes.Status401Unauthorized, "Authentication is required.");
        }

        return base.RedirectToLogin(context);
    }

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        if (IsApiRequest(context.Request))
        {
            return WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "You are not allowed to perform this action.");
        }

        return base.RedirectToAccessDenied(context);
    }

    private static async Task RejectAsync(CookieValidatePrincipalContext context)
    {
        context.HttpContext.SetCurrentSession(null);
        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(SessionDefaults.Scheme);
    }

    private static bool IsApiRequest(HttpRequest request) => request.Path.StartsWithSegments("/api");

    private static Task WriteProblemAsync(HttpContext http, int status, string detail)
    {
        http.Response.StatusCode = status;
        return http.Response.WriteAsJsonAsync(
            new ProblemDetails { Status = status, Title = status == 401 ? "Unauthorized" : "Forbidden", Detail = detail },
            options: null,
            contentType: "application/problem+json");
    }
}
