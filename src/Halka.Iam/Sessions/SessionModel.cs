using System.Security.Claims;

namespace Halka.Iam.Sessions;

public static class SessionDefaults
{
    public const string Scheme = "Halka.Session";
    public const string CookieName = "__Host-halka-session";
    public const string SubjectClaim = "sub";
    public const string SessionIdClaim = "sid";
    public const string NameClaim = "name";
    public const string RoleClaim = "role";
}

public static class Amr
{
    public const string Password = "pwd";
    public const string Otp = "otp";
    public const string Mfa = "mfa";

    public static string Join(IEnumerable<string> values) => string.Join(' ', values.Distinct(StringComparer.Ordinal));

    public static string[] Split(string value) => value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
}

public sealed class CentralSessionOptions
{
    public const string SectionName = "Sessions";

    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(60);

    public TimeSpan AbsoluteLifetime { get; set; } = TimeSpan.FromHours(12);

    /// <summary>How recent a password/MFA verification must be for sensitive actions.</summary>
    public TimeSpan StepUpWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Minimum interval between last-seen writes for the same session.</summary>
    public TimeSpan TouchInterval { get; set; } = TimeSpan.FromMinutes(1);
}

public static class SessionEndReason
{
    public const string Logout = "logout";
    public const string LogoutAll = "logout_all";
    public const string Replaced = "replaced";
    public const string UserRevoked = "user_revoked";
    public const string AdminRevoked = "admin_revoked";
    public const string PasswordChanged = "password_changed";
    public const string PasswordReset = "password_reset";
    public const string MfaChanged = "mfa_changed";
    public const string UserDisabled = "user_disabled";
    public const string IdleTimeout = "idle_timeout";
    public const string AbsoluteTimeout = "absolute_timeout";
    public const string KeyCompromise = "key_compromise";
}

/// <summary>Server-side view of the validated central session for the current request (always loaded from the database).</summary>
public sealed record CurrentSession(
    Guid Id,
    Guid UserId,
    string Email,
    string DisplayName,
    DateTimeOffset AuthTime,
    IReadOnlyList<string> Amr,
    DateTimeOffset PasswordVerifiedAt,
    DateTimeOffset? MfaVerifiedAt,
    DateTimeOffset AbsoluteExpiresAt,
    IReadOnlyList<string> Roles,
    bool MfaEnabled)
{
    public bool HasMfa => Amr.Contains(Sessions.Amr.Mfa, StringComparer.Ordinal);

    public bool IsInRole(string role) => Roles.Contains(role, StringComparer.Ordinal);

    /// <summary>
    /// Step-up freshness: accounts with MFA need a recent second factor; accounts without MFA need a recent password.
    /// </summary>
    public bool IsStepUpFresh(DateTimeOffset now, TimeSpan window)
        => MfaEnabled
            ? MfaVerifiedAt is { } mfa && now - mfa <= window
            : now - PasswordVerifiedAt <= window;

    public bool IsPasswordFresh(DateTimeOffset now, TimeSpan window) => now - PasswordVerifiedAt <= window;
}

public static class SessionPrincipal
{
    /// <summary>Minimal principal stored in the cookie ticket: subject and session identifiers only.</summary>
    public static ClaimsPrincipal ForTicket(Guid userId, Guid sessionId)
    {
        var identity = new ClaimsIdentity(SessionDefaults.Scheme, SessionDefaults.NameClaim, SessionDefaults.RoleClaim);
        identity.AddClaim(new Claim(SessionDefaults.SubjectClaim, userId.ToString()));
        identity.AddClaim(new Claim(SessionDefaults.SessionIdClaim, sessionId.ToString()));
        return new ClaimsPrincipal(identity);
    }

    /// <summary>Per-request principal rebuilt from the database so roles are never taken from the cookie.</summary>
    public static ClaimsPrincipal ForRequest(CurrentSession session)
    {
        var identity = new ClaimsIdentity(SessionDefaults.Scheme, SessionDefaults.NameClaim, SessionDefaults.RoleClaim);
        identity.AddClaim(new Claim(SessionDefaults.SubjectClaim, session.UserId.ToString()));
        identity.AddClaim(new Claim(SessionDefaults.SessionIdClaim, session.Id.ToString()));
        identity.AddClaim(new Claim(SessionDefaults.NameClaim, session.DisplayName.Length > 0 ? session.DisplayName : session.Email));
        foreach (var role in session.Roles)
        {
            identity.AddClaim(new Claim(SessionDefaults.RoleClaim, role));
        }

        return new ClaimsPrincipal(identity);
    }

    public static bool TryRead(ClaimsPrincipal? principal, out Guid userId, out Guid sessionId)
    {
        userId = default;
        sessionId = default;
        return principal?.Identity?.IsAuthenticated == true
               && Guid.TryParse(principal.FindFirstValue(SessionDefaults.SubjectClaim), out userId)
               && Guid.TryParse(principal.FindFirstValue(SessionDefaults.SessionIdClaim), out sessionId);
    }
}

public static class ClientLabel
{
    /// <summary>Reduces a User-Agent header to a coarse "browser on platform" label; the raw header is never stored.</summary>
    public static string FromUserAgent(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return "Unknown client";
        }

        var browser = userAgent switch
        {
            _ when userAgent.Contains("Edg/", StringComparison.Ordinal) => "Edge",
            _ when userAgent.Contains("Firefox/", StringComparison.Ordinal) => "Firefox",
            _ when userAgent.Contains("Chrome/", StringComparison.Ordinal) => "Chrome",
            _ when userAgent.Contains("Safari/", StringComparison.Ordinal) => "Safari",
            _ => "Other browser",
        };
        var platform = userAgent switch
        {
            _ when userAgent.Contains("Windows", StringComparison.Ordinal) => "Windows",
            _ when userAgent.Contains("Android", StringComparison.Ordinal) => "Android",
            _ when userAgent.Contains("iPhone", StringComparison.Ordinal) || userAgent.Contains("iPad", StringComparison.Ordinal) => "iOS",
            _ when userAgent.Contains("Mac OS X", StringComparison.Ordinal) => "macOS",
            _ when userAgent.Contains("Linux", StringComparison.Ordinal) => "Linux",
            _ => "other platform",
        };
        return $"{browser} on {platform}";
    }
}
