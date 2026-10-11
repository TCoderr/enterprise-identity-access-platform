using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Halka.Shared;

public static class SecurityHeaders
{
    /// <summary>
    /// Content-Security-Policy without external origins and without inline script/style. "form-action" is intentionally
    /// absent: OIDC flows redirect to registered client origins after form submissions and Chrome applies form-action
    /// to the whole redirect chain.
    /// </summary>
    public const string ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    public static IApplicationBuilder UseHalkaSecurityHeaders(this IApplicationBuilder app)
        => app.Use(async (context, next) =>
        {
            context.Response.OnStarting(static state =>
            {
                var headers = ((HttpContext)state).Response.Headers;
                headers["X-Content-Type-Options"] = "nosniff";
                headers["X-Frame-Options"] = "DENY";
                headers["Referrer-Policy"] = "no-referrer";
                headers["Cross-Origin-Opener-Policy"] = "same-origin";
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
                headers["Strict-Transport-Security"] = "max-age=31536000";
                if (!headers.ContainsKey("Content-Security-Policy"))
                {
                    headers["Content-Security-Policy"] = ContentSecurityPolicy;
                }

                // Everything that is not an explicitly cacheable static asset is treated as sensitive.
                if (!headers.ContainsKey("Cache-Control"))
                {
                    headers["Cache-Control"] = "no-store";
                    headers["Pragma"] = "no-cache";
                }

                return Task.CompletedTask;
            }, context);

            await next();
        });
}
