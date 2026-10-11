using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Halka.DemoClient;

public sealed record WorkspaceNote(Guid Id, string Text, string Author, DateTimeOffset CreatedAt);

/// <summary>Outcome of one API call as shown to the user: status and a short explanation, never a token.</summary>
public sealed record ApiCallResult(string Operation, int StatusCode, string Summary, IReadOnlyList<WorkspaceNote> Notes)
{
    public bool Succeeded => StatusCode is >= 200 and < 300;
}

/// <summary>
/// Calls the protected Workspace API on behalf of the signed-in user. The access token is attached on the server;
/// the browser never sees it.
/// </summary>
public sealed class WorkspaceApiClient(IHttpClientFactory clients, IOptions<DemoClientOptions> options)
{
    public const string HttpClientName = "workspace-api";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Task<ApiCallResult> ListAsync(string accessToken, CancellationToken cancellationToken)
        => SendAsync("Load notes", HttpMethod.Get, "/notes", null, accessToken, cancellationToken);

    public Task<ApiCallResult> ListSensitiveAsync(string accessToken, CancellationToken cancellationToken)
        => SendAsync("Load sensitive notes", HttpMethod.Get, "/notes/sensitive", null, accessToken, cancellationToken);

    public Task<ApiCallResult> AddAsync(string accessToken, string text, CancellationToken cancellationToken)
        => SendAsync("Add note", HttpMethod.Post, "/notes", JsonContent.Create(new { text }), accessToken, cancellationToken);

    private async Task<ApiCallResult> SendAsync(string operation, HttpMethod method, string path, HttpContent? content, string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, options.Value.ApiBaseUrl.TrimEnd('/') + path) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage response;
        try
        {
            response = await clients.CreateClient(HttpClientName).SendAsync(request, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or IOException)
        {
            return new ApiCallResult(operation, 0, "The Workspace API could not be reached.", []);
        }

        using (response)
        {
            var status = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                var notes = method == HttpMethod.Get
                    ? await response.Content.ReadFromJsonAsync<List<WorkspaceNote>>(Json, cancellationToken) ?? []
                    : [(await response.Content.ReadFromJsonAsync<WorkspaceNote>(Json, cancellationToken))!];
                return new ApiCallResult(operation, status, method == HttpMethod.Get ? $"{notes.Count} note(s) returned." : "The note was added.", notes);
            }

            return new ApiCallResult(operation, status, await DescribeAsync(response, cancellationToken), []);
        }
    }

    /// <summary>Maps the API's standard error signals to a short explanation.</summary>
    private static async Task<string> DescribeAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var challenge = response.Headers.WwwAuthenticate.ToString();
        if ((int)response.StatusCode == 401)
        {
            return "The API rejected the access token (invalid, expired or revoked).";
        }

        if ((int)response.StatusCode == 403 && challenge.Contains("insufficient_scope", StringComparison.Ordinal))
        {
            return "Insufficient scope: this application was not granted the permission this operation needs.";
        }

        if ((int)response.StatusCode == 503)
        {
            return "The API could not verify the token because the identity provider is unavailable. No access was granted.";
        }

        try
        {
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            if (problem.RootElement.TryGetProperty("detail", out var detail) && detail.GetString() is { Length: > 0 } text)
            {
                return text;
            }
        }
        catch (JsonException)
        {
        }

        return "The API refused the request.";
    }
}
