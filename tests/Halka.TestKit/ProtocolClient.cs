using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Halka.TestKit;

public sealed record AuthorizationOutcome(string? Code, string? Error, string? ErrorDescription, string? State, Uri? Redirect, Page? Page)
{
    public bool ReturnedToClient => Redirect is not null;
}

public sealed record ProtocolResponse(HttpStatusCode Status, JsonElement Json, HttpResponseMessage Raw)
{
    public string? String(string name) => Json.ValueKind == JsonValueKind.Object && Json.TryGetProperty(name, out var value) ? value.GetString() : null;

    public bool Has(string name) => Json.ValueKind == JsonValueKind.Object && Json.TryGetProperty(name, out _);

    public string? Error => String("error");

    public string AccessToken => String("access_token") ?? throw new InvalidOperationException($"No access token in response ({(int)Status} {Error}).");

    public string RefreshToken => String("refresh_token") ?? throw new InvalidOperationException($"No refresh token in response ({(int)Status} {Error}).");

    public string IdToken => String("id_token") ?? throw new InvalidOperationException($"No ID token in response ({(int)Status} {Error}).");
}

public sealed record Pkce(string Verifier, string Challenge)
{
    public static Pkce Create()
    {
        var verifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }
}

/// <summary>
/// A hand-driven OAuth/OIDC client for protocol tests. Every step is a real HTTPS request to the protocol endpoints
/// of the running identity provider; nothing is created through library APIs behind its back.
/// </summary>
public sealed class ProtocolClient(HalkaStack stack, string clientId, string clientSecret, string redirectUri) : IDisposable
{
    private readonly Browser _backchannel = stack.NewBrowser();

    public string ClientId { get; } = clientId;

    public string ClientSecret { get; } = clientSecret;

    public string RedirectUri { get; } = redirectUri;

    public static ProtocolClient Pano(HalkaStack stack) => new(stack, Halka.Migrator.DemoCatalog.PanoClientId, stack.Demo.PanoSecret, $"{stack.PanoOrigin}/signin-oidc");

    public static ProtocolClient Rapor(HalkaStack stack) => new(stack, Halka.Migrator.DemoCatalog.RaporClientId, stack.Demo.RaporSecret, $"{stack.RaporOrigin}/signin-oidc");

    public string AuthorizeUrl(string scope, Pkce? pkce, string? state = "state-1", string? nonce = "nonce-1", IReadOnlyDictionary<string, string?>? overrides = null)
    {
        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["client_id"] = ClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = RedirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = pkce?.Challenge,
            ["code_challenge_method"] = pkce is null ? null : "S256",
        };
        foreach (var (key, value) in overrides ?? new Dictionary<string, string?>())
        {
            parameters[key] = value;
        }

        return QueryHelpers.AddQueryString($"{stack.IamOrigin}/connect/authorize", parameters.Where(pair => pair.Value is not null));
    }

    /// <summary>
    /// Drives an authorization request like a user would: follows redirects inside the identity provider, signs in
    /// when a login form appears (if a user is given) and answers the consent screen. It stops when the provider
    /// redirects back to the client (the client itself is not contacted) or shows a page it cannot continue from.
    /// </summary>
    public async Task<AuthorizationOutcome> AuthorizeAsync(Browser browser, string url, TestUser? user = null, string? consent = "allow")
    {
        var page = await browser.GetAsync(url, follow: false);
        for (var step = 0; step < 20; step++)
        {
            if ((int)page.Status is 301 or 302 or 303 or 307 or 308 && page.Response.Headers.Location is { } location)
            {
                var target = new Uri(page.Url, location);
                if (!string.Equals(target.Authority, new Uri(stack.IamOrigin).Authority, StringComparison.OrdinalIgnoreCase))
                {
                    var query = QueryHelpers.ParseQuery(target.Query);
                    return new AuthorizationOutcome(
                        query.TryGetValue("code", out var code) ? code.ToString() : null,
                        query.TryGetValue("error", out var error) ? error.ToString() : null,
                        query.TryGetValue("error_description", out var description) ? description.ToString() : null,
                        query.TryGetValue("state", out var returnedState) ? returnedState.ToString() : null,
                        target,
                        null);
                }

                page = await browser.GetAsync(target.ToString(), follow: false);
                continue;
            }

            if (page.Status == HttpStatusCode.OK && user is not null && page.Find("form[action*='/account/login']") is not null)
            {
                page = await browser.SubmitAsync(page, "form[action*='/account/login']", new Dictionary<string, string>
                {
                    ["Input.Email"] = user.Email,
                    ["Input.Password"] = user.Password,
                }, follow: false);
                user = null;
                continue;
            }

            if (page.Status == HttpStatusCode.OK && consent is not null && page.Find("form[action='/connect/authorize']") is not null)
            {
                page = await browser.SubmitAsync(page, "form[action='/connect/authorize']", new Dictionary<string, string> { ["consent_decision"] = consent }, follow: false);
                consent = null;
                continue;
            }

            return new AuthorizationOutcome(null, null, null, null, null, page);
        }

        throw new InvalidOperationException("The authorization request did not complete.");
    }

    /// <summary>Signs in (when needed), consents and exchanges the code: the full code flow with PKCE.</summary>
    public async Task<ProtocolResponse> SignInAsync(Browser browser, TestUser user, string scope)
    {
        var pkce = Pkce.Create();
        var outcome = await AuthorizeAsync(browser, AuthorizeUrl(scope, pkce), user);
        if (outcome.Code is null)
        {
            throw new InvalidOperationException($"Authorization did not return a code (error: {outcome.Error ?? "none"}, page: {outcome.Page?.Url.AbsolutePath}).");
        }

        return await ExchangeCodeAsync(outcome.Code, pkce.Verifier);
    }

    public Task<ProtocolResponse> ExchangeCodeAsync(string code, string? verifier, string? redirectUriOverride = null, string? clientIdOverride = null, string? secretOverride = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUriOverride ?? RedirectUri,
        };
        if (verifier is not null)
        {
            form["code_verifier"] = verifier;
        }

        return PostAsync("/connect/token", form, clientIdOverride ?? ClientId, secretOverride ?? ClientSecret);
    }

    public Task<ProtocolResponse> RefreshAsync(string refreshToken, string? scope = null)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken };
        if (scope is not null)
        {
            form["scope"] = scope;
        }

        return PostAsync("/connect/token", form, ClientId, ClientSecret);
    }

    public Task<ProtocolResponse> ClientCredentialsAsync(string? scope, string? secretOverride = null)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "client_credentials" };
        if (scope is not null)
        {
            form["scope"] = scope;
        }

        return PostAsync("/connect/token", form, ClientId, secretOverride ?? ClientSecret);
    }

    public Task<ProtocolResponse> IntrospectAsync(string token, string? hint = null)
    {
        var form = new Dictionary<string, string> { ["token"] = token };
        if (hint is not null)
        {
            form["token_type_hint"] = hint;
        }

        return PostAsync("/connect/introspect", form, ClientId, ClientSecret);
    }

    public Task<ProtocolResponse> RevokeAsync(string token, string? hint = null, string? secretOverride = null)
    {
        var form = new Dictionary<string, string> { ["token"] = token };
        if (hint is not null)
        {
            form["token_type_hint"] = hint;
        }

        return PostAsync("/connect/revoke", form, ClientId, secretOverride ?? ClientSecret);
    }

    public Task<ProtocolResponse> UserInfoAsync(string accessToken)
        => SendAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"{stack.IamOrigin}/connect/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            return request;
        });

    /// <summary>Calls the Workspace API with a bearer token (or without one).</summary>
    public Task<ProtocolResponse> ApiAsync(HttpMethod method, string path, string? bearer, string? jsonBody = null)
        => SendAsync(() =>
        {
            var request = new HttpRequestMessage(method, $"{stack.ApiOrigin}{path}");
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            if (jsonBody is not null)
            {
                request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            }

            return request;
        });

    public Task<ProtocolResponse> PostAsync(string path, IReadOnlyDictionary<string, string> form, string? basicClientId, string? basicSecret)
        => SendAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, $"{stack.IamOrigin}{path}") { Content = new FormUrlEncodedContent(form) };
            if (basicClientId is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(
                    Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(basicClientId)}:{Uri.EscapeDataString(basicSecret ?? string.Empty)}")));
            }

            return request;
        });

    public async Task<ProtocolResponse> SendAsync(Func<HttpRequestMessage> requestFactory)
    {
        var response = await _backchannel.Http.SendAsync(requestFactory());
        var body = await response.Content.ReadAsStringAsync();
        JsonElement json = default;
        if (body.Length > 0 && response.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.Ordinal) == true)
        {
            json = JsonDocument.Parse(body).RootElement.Clone();
        }

        return new ProtocolResponse(response.StatusCode, json, response);
    }

    public void Dispose() => _backchannel.Dispose();
}
