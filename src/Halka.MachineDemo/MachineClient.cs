using System.Net.Http.Headers;
using System.Text.Json;
using Halka.Shared;
using Microsoft.Extensions.Configuration;

namespace Halka.MachineDemo;

public sealed record MachineReport(bool Succeeded, IReadOnlyList<string> Lines);

public sealed record TokenResult(int StatusCode, string? AccessToken, string? Error, bool HasIdToken, bool HasRefreshToken, string? Scope);

/// <summary>
/// A machine client acts as itself: it authenticates with its own credentials, receives an access token whose
/// subject is the client, and gets neither an ID token nor a refresh token. Only masked values are reported.
/// </summary>
public static class MachineClient
{
    public static async Task<MachineReport> RunAsync(IConfiguration configuration, CancellationToken cancellationToken)
    {
        var section = configuration.GetSection("Machine");
        var authority = Require(section, "Authority").TrimEnd('/');
        var api = Require(section, "ApiBaseUrl").TrimEnd('/');
        var clientId = section["ClientId"] ?? "ops-machine";
        var secret = SecretFile.Resolve(section, "ClientSecret") ?? throw new InvalidOperationException("Machine:ClientSecret (or ClientSecretFile) is not configured.");
        var scopes = section["Scopes"] ?? "workspace.read workspace.jobs";

        var backchannelOptions = configuration.GetSection(BackchannelOptions.SectionName).Get<BackchannelOptions>() ?? new BackchannelOptions();
        using var backchannel = new BackchannelHttp(backchannelOptions);
        using var http = new HttpClient(backchannel.CreateHandler()) { Timeout = backchannel.Timeout };

        var lines = new List<string>();
        var token = await RequestTokenAsync(http, authority, clientId, secret, scopes, cancellationToken);
        lines.Add($"token request: {token.StatusCode}{(token.Error is null ? string.Empty : $" error={token.Error}")}");
        if (token.AccessToken is null)
        {
            return new MachineReport(false, lines);
        }

        lines.Add($"access token: {Mask(token.AccessToken)} scope=\"{token.Scope}\" id_token={(token.HasIdToken ? "present" : "none")} refresh_token={(token.HasRefreshToken ? "present" : "none")}");
        var jobs = await CallAsync(http, HttpMethod.Get, $"{api}/jobs/status", token.AccessToken, cancellationToken);
        var read = await CallAsync(http, HttpMethod.Get, $"{api}/notes", token.AccessToken, cancellationToken);
        var write = await CallAsync(http, HttpMethod.Post, $"{api}/notes", token.AccessToken, cancellationToken);
        lines.Add($"GET /jobs/status (workspace.jobs): {jobs}");
        lines.Add($"GET /notes (workspace.read): {read}");
        lines.Add($"POST /notes (not permitted for this client): {write}");
        var succeeded = jobs == 200 && read == 200 && write == 403 && !token.HasIdToken && !token.HasRefreshToken;
        lines.Add(succeeded ? "result: ok (least privilege confirmed)" : "result: unexpected");
        return new MachineReport(succeeded, lines);
    }

    public static async Task<TokenResult> RequestTokenAsync(HttpClient http, string authority, string clientId, string secret, string scopes, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{authority}/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["scope"] = scopes }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}")));
        using var response = await http.SendAsync(request, cancellationToken);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var root = document.RootElement;
        return new TokenResult(
            (int)response.StatusCode,
            root.TryGetProperty("access_token", out var accessToken) ? accessToken.GetString() : null,
            root.TryGetProperty("error", out var error) ? error.GetString() : null,
            root.TryGetProperty("id_token", out _),
            root.TryGetProperty("refresh_token", out _),
            root.TryGetProperty("scope", out var scope) ? scope.GetString() : scopes);
    }

    private static async Task<int> CallAsync(HttpClient http, HttpMethod method, string url, string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (method == HttpMethod.Post)
        {
            request.Content = new StringContent("{\"text\":\"written by a machine\"}", System.Text.Encoding.UTF8, "application/json");
        }

        using var response = await http.SendAsync(request, cancellationToken);
        return (int)response.StatusCode;
    }

    /// <summary>Shows only the length and the last four characters of a token.</summary>
    public static string Mask(string value) => value.Length <= 8 ? "****" : $"****{value[^4..]} ({value.Length} chars)";

    private static string Require(IConfigurationSection section, string key)
        => section[key] is { Length: > 0 } value ? value : throw new InvalidOperationException($"Machine:{key} is not configured.");
}
