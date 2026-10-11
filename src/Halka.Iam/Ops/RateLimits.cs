using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Ops;

public sealed class RateLimitOptions
{
    public const string SectionName = "RateLimits";

    /// <summary>Password attempts per minute for one (address, account name) pair.</summary>
    public int LoginPerAccountPerMinute { get; set; } = 10;

    /// <summary>Sign-in form posts per minute for one address, across all account names.</summary>
    public int LoginPerAddressPerMinute { get; set; } = 60;

    public int MfaPerMinute { get; set; } = 10;

    /// <summary>Forgot/reset/confirm posts per minute for one address.</summary>
    public int RecoveryPerMinute { get; set; } = 5;

    public int SignupPerHour { get; set; } = 10;

    /// <summary>Token endpoint requests per minute for one (client, address) pair.</summary>
    public int TokenPerMinute { get; set; } = 120;
}

public static class RateLimitPolicies
{
    public const string LoginAddress = "login-address";
    public const string Mfa = "mfa";
    public const string Recovery = "recovery";
    public const string Signup = "signup";
    public const string Token = "token";

    /// <summary>
    /// Registers partitioned limiters. Each policy has its own dimension, so one noisy client or address cannot
    /// exhaust a bucket shared by everyone. Only state-changing requests are counted.
    /// </summary>
    public static IServiceCollection AddHalkaRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<RateLimitOptions>(configuration.GetSection(RateLimitOptions.SectionName));
        var limits = configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>() ?? new RateLimitOptions();

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = static async (context, cancellationToken) =>
            {
                var response = context.HttpContext.Response;
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                }

                response.ContentType = "text/plain; charset=utf-8";
                await response.WriteAsync("Too many requests. Please wait a moment and try again.", cancellationToken);
            };

            options.AddPolicy(LoginAddress, http => PostsByAddress(http, "login", limits.LoginPerAddressPerMinute, TimeSpan.FromMinutes(1)));
            options.AddPolicy(Mfa, http => PostsByAddress(http, "mfa", limits.MfaPerMinute, TimeSpan.FromMinutes(1)));
            options.AddPolicy(Recovery, http => PostsByAddress(http, "recovery", limits.RecoveryPerMinute, TimeSpan.FromMinutes(1)));
            options.AddPolicy(Signup, http => PostsByAddress(http, "signup", limits.SignupPerHour, TimeSpan.FromHours(1)));
            options.AddPolicy(Token, http =>
            {
                // The client identifier is read from Basic credentials or left empty; the form body is not parsed here.
                var client = ClientIdFromBasic(http.Request.Headers.Authorization.ToString());
                return Window($"token:{Address(http)}:{client}", limits.TokenPerMinute, TimeSpan.FromMinutes(1));
            });
        });

        services.AddSingleton<AccountAttemptLimiter>();
        return services;
    }

    private static RateLimitPartition<string> PostsByAddress(HttpContext http, string name, int limit, TimeSpan window)
        => HttpMethods.IsPost(http.Request.Method)
            ? Window($"{name}:{Address(http)}", limit, window)
            : RateLimitPartition.GetNoLimiter($"{name}:read");

    private static RateLimitPartition<string> Window(string key, int limit, TimeSpan window)
        => RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, limit),
            Window = window,
            QueueLimit = 0,
            AutoReplenishment = true,
        });

    internal static string Address(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static string ClientIdFromBasic(string authorization)
    {
        if (!authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return "-";
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authorization["Basic ".Length..].Trim()));
            var separator = decoded.IndexOf(':', StringComparison.Ordinal);
            var client = separator > 0 ? decoded[..separator] : "-";
            return client.Length <= 64 ? client : "-";
        }
        catch (FormatException)
        {
            return "-";
        }
    }
}

/// <summary>
/// Limits password attempts per (address, account name). The key is hashed so neither value is kept in memory in
/// clear text, and the account dimension keeps one targeted account from consuming the budget of others.
/// </summary>
public sealed class AccountAttemptLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter;

    public AccountAttemptLimiter(IOptions<RateLimitOptions> options)
    {
        var limit = Math.Max(1, options.Value.LoginPerAccountPerMinute);
        _limiter = PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetFixedWindowLimiter(
            key,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = limit,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
    }

    public bool TryAcquire(string address, string normalizedAccount)
    {
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{address}\n{normalizedAccount}")));
        using var lease = _limiter.AttemptAcquire(key);
        return lease.IsAcquired;
    }

    public void Dispose() => _limiter.Dispose();
}
