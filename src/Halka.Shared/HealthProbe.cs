using Microsoft.Extensions.Configuration;

namespace Halka.Shared;

/// <summary>
/// Container health probe built into each application ("--healthcheck"), so images need no curl or shell tooling.
/// It calls the application's own readiness endpoint over HTTPS on loopback, validating the certificate against
/// the configured local CA and the public host name.
/// </summary>
public static class HealthProbe
{
    public const string Argument = "--healthcheck";

    public static bool IsRequested(string[] args) => args.Contains(Argument, StringComparer.Ordinal);

    public static async Task<int> RunAsync(IConfiguration configuration, string path = "/health/ready")
    {
        var endpoint = configuration["Kestrel:Endpoints:Https:Url"];
        var publicHost = configuration["HealthProbe:Host"] ?? configuration["AllowedHosts"]?.Split(';')[0];
        if (!Uri.TryCreate(endpoint?.Replace("+", "localhost", StringComparison.Ordinal).Replace("*", "localhost", StringComparison.Ordinal), UriKind.Absolute, out var listen)
            || string.IsNullOrWhiteSpace(publicHost))
        {
            return 2;
        }

        var options = configuration.GetSection(BackchannelOptions.SectionName).Get<BackchannelOptions>() ?? new BackchannelOptions();
        using var backchannel = new BackchannelHttp(options);
        using var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false };
        backchannel.Apply(handler);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4) };
        using var request = new HttpRequestMessage(HttpMethod.Get, new UriBuilder("https", "127.0.0.1", listen.Port, path).Uri);
        request.Headers.Host = $"{publicHost}:{listen.Port}";
        try
        {
            using var response = await client.SendAsync(request);
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return 1;
        }
    }
}
