using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Halka.DemoClient;

public sealed class DemoClientOptions
{
    public const string SectionName = "Client";

    public string Name { get; set; } = string.Empty;

    public string Slug { get; set; } = string.Empty;

    public string Theme { get; set; } = string.Empty;

    public string Tagline { get; set; } = string.Empty;

    /// <summary>Whether this application offers the "add note" action (it still depends on the granted scope).</summary>
    public bool CanWrite { get; set; }

    public string PublicOrigin { get; set; } = string.Empty;

    /// <summary>Issuer of the identity provider.</summary>
    public string Authority { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string ApiBaseUrl { get; set; } = string.Empty;

    public List<string> Scopes { get; set; } = [];

    /// <summary>Tokens are refreshed when they expire within this many seconds.</summary>
    public int RefreshSkewSeconds { get; set; } = 60;

    /// <summary>
    /// How long a positive session check may be reused. 0 (default) checks the identity provider on every request,
    /// so central logout and revocation take effect immediately. Any other value is the maximum revocation delay.
    /// </summary>
    public int SessionValidationCacheSeconds { get; set; }
}

/// <summary>The identity provider could not be reached or answered with a server error. Nothing is granted.</summary>
public sealed class AuthorizationServerUnavailableException(string message, Exception? innerException = null)
    : Exception(message, innerException);

/// <summary>
/// Back-channel calls of the BFF to the identity provider: refresh, introspection and revocation. These are plain
/// OAuth requests authenticated with the client secret; token contents are never parsed or validated here.
/// </summary>
public sealed class OpClient(
    IHttpClientFactory clients,
    IOptionsMonitor<OpenIdConnectOptions> oidc,
    IOptions<DemoClientOptions> options,
    ClientSecretAccessor secret,
    TimeProvider time)
{
    public const string HttpClientName = "identity-provider";

    public async Task<OpenIdConnectConfiguration> ConfigurationAsync(CancellationToken cancellationToken)
    {
        try
        {
            var manager = oidc.Get(DemoClientHost.OidcScheme).ConfigurationManager
                          ?? throw new InvalidOperationException("The OpenID Connect configuration manager is not available.");
            return await manager.GetConfigurationAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is InvalidOperationException or HttpRequestException or TaskCanceledException or IOException)
        {
            throw new AuthorizationServerUnavailableException("The identity provider metadata could not be loaded.", exception);
        }
    }

    /// <summary>Exchanges the refresh token. Returns null when the grant is no longer valid (the session has ended).</summary>
    public async Task<TokenSet?> RefreshAsync(TokenSet current, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(current.RefreshToken))
        {
            return null;
        }

        var configuration = await ConfigurationAsync(cancellationToken);
        using var response = await PostAsync(configuration.TokenEndpoint, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = current.RefreshToken,
        }, cancellationToken);
        if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
        {
            return null;
        }

        using var document = await ReadJsonAsync(response, cancellationToken);
        var root = document.RootElement;
        var accessToken = root.GetProperty("access_token").GetString() ?? throw new AuthorizationServerUnavailableException("The token response is incomplete.");
        var expiresIn = root.TryGetProperty("expires_in", out var seconds) ? seconds.GetInt32() : 0;
        var scopes = root.TryGetProperty("scope", out var scope) && scope.GetString() is { Length: > 0 } value
            ? value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : current.Scopes;
        return new TokenSet(
            accessToken,
            root.TryGetProperty("refresh_token", out var refresh) ? refresh.GetString() : null,
            root.TryGetProperty("id_token", out var idToken) ? idToken.GetString() ?? current.IdToken : current.IdToken,
            time.GetUtcNow().AddSeconds(expiresIn),
            scopes);
    }

    /// <summary>Asks the identity provider whether the access token is still active (server-side session state).</summary>
    public async Task<bool> IsActiveAsync(string accessToken, CancellationToken cancellationToken)
    {
        var configuration = await ConfigurationAsync(cancellationToken);
        using var response = await PostAsync(configuration.IntrospectionEndpoint, new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["token_type_hint"] = "access_token",
        }, cancellationToken);
        if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
        {
            return false;
        }

        using var document = await ReadJsonAsync(response, cancellationToken);
        return document.RootElement.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.True;
    }

    /// <summary>Revokes one of this client's tokens (RFC 7009). Best effort: local logout proceeds either way.</summary>
    public async Task<bool> TryRevokeAsync(string token, string hint, CancellationToken cancellationToken)
    {
        try
        {
            var configuration = await ConfigurationAsync(cancellationToken);
            if (configuration.RevocationEndpoint is not { Length: > 0 } address)
            {
                return false;
            }

            using var response = await PostAsync(address, new Dictionary<string, string> { ["token"] = token, ["token_type_hint"] = hint }, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (AuthorizationServerUnavailableException)
        {
            return false;
        }
    }

    private async Task<HttpResponseMessage> PostAsync(string endpoint, Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        form["client_id"] = options.Value.ClientId;
        form["client_secret"] = secret.Value;
        var client = clients.CreateClient(HttpClientName);
        HttpResponseMessage response;
        try
        {
            response = await client.PostAsync(endpoint, new FormUrlEncodedContent(form), cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or IOException)
        {
            throw new AuthorizationServerUnavailableException("The identity provider could not be reached.", exception);
        }

        if ((int)response.StatusCode >= 500 || response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            response.Dispose();
            throw new AuthorizationServerUnavailableException("The identity provider is temporarily unavailable.");
        }

        return response;
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or IOException)
        {
            throw new AuthorizationServerUnavailableException("The identity provider returned an unexpected response.", exception);
        }
    }
}

/// <summary>Holds the client secret read from configuration or a private file at start-up. It is never logged or rendered.</summary>
public sealed class ClientSecretAccessor(string value)
{
    public string Value { get; } = value;

    public override string ToString() => "[client secret]";
}

/// <summary>
/// Per-request guard of the application session: refreshes tokens shortly before they expire (single flight) and
/// confirms with the identity provider that the session behind them is still alive.
/// </summary>
public sealed class SessionGuard(
    AppSessionStore store,
    SessionLocks locks,
    OpClient op,
    SessionValidationCache cache,
    TimeProvider time,
    IOptions<DemoClientOptions> options)
{
    /// <summary>Returns the live session, or null when it has ended (the row is deleted in that case).</summary>
    public async Task<StoredSession?> EnsureActiveAsync(Guid sessionId, bool forceRefresh, CancellationToken cancellationToken)
    {
        var session = await store.FindAsync(sessionId, cancellationToken);
        if (session is null)
        {
            return null;
        }

        var now = time.GetUtcNow();
        if (forceRefresh || session.Tokens.ExpiresAt - now <= TimeSpan.FromSeconds(options.Value.RefreshSkewSeconds))
        {
            session = await RefreshAsync(session, cancellationToken);
            if (session is null)
            {
                return await EndAsync(sessionId, cancellationToken);
            }
        }

        var cacheFor = TimeSpan.FromSeconds(Math.Max(0, options.Value.SessionValidationCacheSeconds));
        if (cache.IsFresh(sessionId, session.Version, now, cacheFor))
        {
            return session;
        }

        if (!await op.IsActiveAsync(session.Tokens.AccessToken, cancellationToken))
        {
            return await EndAsync(sessionId, cancellationToken);
        }

        cache.Remember(sessionId, session.Version, now);
        return session;
    }

    public async Task<StoredSession?> EndAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        await store.DeleteAsync(sessionId, cancellationToken);
        locks.Forget(sessionId);
        cache.Forget(sessionId);
        return null;
    }

    private async Task<StoredSession?> RefreshAsync(StoredSession observed, CancellationToken cancellationToken)
    {
        using var gate = await locks.AcquireAsync(observed.Id, cancellationToken);

        // Re-read under the gate: a request that waited here finds the tokens its predecessor just obtained and
        // must not present the already rotated refresh token again.
        var current = await store.FindAsync(observed.Id, cancellationToken);
        if (current is null)
        {
            return null;
        }

        if (current.Version != observed.Version)
        {
            return current;
        }

        var refreshed = await op.RefreshAsync(current.Tokens, cancellationToken);
        if (refreshed is null)
        {
            return null;
        }

        return await store.TryUpdateAsync(current.Id, current.Version, refreshed, cancellationToken)
            ? new StoredSession(current.Id, current.Version + 1, refreshed)
            : await store.FindAsync(current.Id, cancellationToken);
    }
}

/// <summary>Optional, bounded reuse of a positive session check (disabled by default).</summary>
public sealed class SessionValidationCache
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, (int Version, DateTimeOffset CheckedAt)> _entries = new();

    public bool IsFresh(Guid sessionId, int version, DateTimeOffset now, TimeSpan lifetime)
        => lifetime > TimeSpan.Zero && _entries.TryGetValue(sessionId, out var entry) && entry.Version == version && now - entry.CheckedAt < lifetime;

    public void Remember(Guid sessionId, int version, DateTimeOffset now) => _entries[sessionId] = (version, now);

    public void Forget(Guid sessionId) => _entries.TryRemove(sessionId, out _);
}
