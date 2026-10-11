using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.DataProtection;
using OpenIddict.Abstractions;

namespace Halka.Iam.Protocol;

/// <summary>
/// Makes "prompt=login" (and "max_age=0") impossible to satisfy with an existing SSO cookie. When such a request
/// first arrives, a protected cookie records a digest of the request, the time of the challenge and the session
/// that existed at that moment. The request only continues with a different session (every sign-in creates a new
/// one) whose authentication time is not older than the challenge, i.e. after the user really authenticated again.
/// </summary>
public sealed class ReauthChallenge(IDataProtectionProvider protection, TimeProvider time)
{
    public const string CookieName = "__Host-halka-reauth";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);
    private readonly IDataProtector _protector = protection.CreateProtector("Halka.Iam.Reauth.v1");

    public bool IsSatisfied(HttpContext http, OpenIddictRequest request, CurrentSession session)
    {
        if (Read(http) is not { } challenge || challenge.RequestDigest != Digest(request))
        {
            return false;
        }

        if (session.Id == challenge.PriorSessionId || session.AuthTime < challenge.IssuedAt)
        {
            return false;
        }

        http.Response.Cookies.Delete(CookieName, CookieOptions(null));
        return true;
    }

    /// <summary>Starts a challenge for this request unless one is already pending for it.</summary>
    public void Issue(HttpContext http, OpenIddictRequest request, CurrentSession? current)
    {
        var digest = Digest(request);
        if (Read(http) is { } pending && pending.RequestDigest == digest)
        {
            return;
        }

        var now = time.GetUtcNow();
        var payload = string.Join('|', digest, now.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture), (current?.Id ?? Guid.Empty).ToString("N"));
        http.Response.Cookies.Append(CookieName, _protector.Protect(payload), CookieOptions(now + Lifetime));
    }

    private (string RequestDigest, DateTimeOffset IssuedAt, Guid PriorSessionId)? Read(HttpContext http)
    {
        if (!http.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var parts = _protector.Unprotect(value).Split('|');
            if (parts.Length != 3
                || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var milliseconds)
                || !Guid.TryParseExact(parts[2], "N", out var priorSessionId))
            {
                return null;
            }

            var issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
            return time.GetUtcNow() - issuedAt > Lifetime ? null : (parts[0], issuedAt, priorSessionId);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static string Digest(OpenIddictRequest request)
    {
        var material = string.Join('\n', request.ClientId, request.RedirectUri, request.State, request.Nonce, request.CodeChallenge, request.Scope);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private static CookieOptions CookieOptions(DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
        Expires = expires,
    };
}
