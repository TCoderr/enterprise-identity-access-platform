using System.Net;
using System.Text.Json;
using Halka.Iam.Data;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Halka.IntegrationTests.Stage3;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class DiscoveryAndCodeFlowTests(StackFixture fixture)
{
    private const string PanoScopes = "openid profile email offline_access workspace.read workspace.write";

    private HalkaStack Stack => fixture.Stack;

    private async Task<JsonElement> GetJsonAsync(string path)
    {
        using var browser = Stack.NewBrowser();
        var page = await browser.GetAsync($"{Stack.IamOrigin}{path}");
        Assert.Equal(HttpStatusCode.OK, page.Status);
        return JsonDocument.Parse(page.Body).RootElement.Clone();
    }

    private static string[] Strings(JsonElement document, string name)
        => document.TryGetProperty(name, out var value) ? value.EnumerateArray().Select(item => item.GetString()!).ToArray() : [];

    [Fact]
    public async Task Discovery_AdvertisesExactlyTheSupportedProtocolSurface()
    {
        var discovery = await GetJsonAsync("/.well-known/openid-configuration");

        Assert.Equal($"{Stack.IamOrigin}/", discovery.GetProperty("issuer").GetString());
        Assert.Equal($"{Stack.IamOrigin}/connect/authorize", discovery.GetProperty("authorization_endpoint").GetString());
        Assert.Equal($"{Stack.IamOrigin}/connect/token", discovery.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{Stack.IamOrigin}/connect/userinfo", discovery.GetProperty("userinfo_endpoint").GetString());
        Assert.Equal($"{Stack.IamOrigin}/connect/introspect", discovery.GetProperty("introspection_endpoint").GetString());
        Assert.Equal($"{Stack.IamOrigin}/connect/revoke", discovery.GetProperty("revocation_endpoint").GetString());
        Assert.Equal($"{Stack.IamOrigin}/connect/endsession", discovery.GetProperty("end_session_endpoint").GetString());
        Assert.Equal($"{Stack.IamOrigin}/.well-known/jwks", discovery.GetProperty("jwks_uri").GetString());

        Assert.Equal(["authorization_code", "client_credentials", "refresh_token"], Strings(discovery, "grant_types_supported").Order());
        Assert.Equal(["code"], Strings(discovery, "response_types_supported"));
        Assert.Equal(["query"], Strings(discovery, "response_modes_supported"));
        Assert.Equal(["S256"], Strings(discovery, "code_challenge_methods_supported"));
        Assert.Equal(["RS256"], Strings(discovery, "id_token_signing_alg_values_supported"));
        Assert.Equal(["public"], Strings(discovery, "subject_types_supported"));
        Assert.Contains("openid", Strings(discovery, "scopes_supported"));
        Assert.DoesNotContain("none", Strings(discovery, "id_token_signing_alg_values_supported"));

        // Flows and features that are out of scope are not advertised.
        var raw = discovery.GetRawText();
        Assert.DoesNotContain("\"password\"", raw);
        Assert.DoesNotContain("\"implicit\"", raw);
        Assert.DoesNotContain("device_authorization_endpoint", raw);
        Assert.DoesNotContain("registration_endpoint", raw);
        Assert.DoesNotContain("acr_values_supported", raw);
        Assert.DoesNotContain("backchannel_logout_supported", raw);
    }

    [Fact]
    public async Task Jwks_PublishesOnlyPublicSigningKeyMaterial()
    {
        var jwks = await GetJsonAsync("/.well-known/jwks");
        var keys = jwks.GetProperty("keys").EnumerateArray().ToList();

        var key = Assert.Single(keys);
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.False(string.IsNullOrEmpty(key.GetProperty("kid").GetString()));
        Assert.True(key.TryGetProperty("n", out _));
        Assert.True(key.TryGetProperty("e", out _));
        foreach (var privateMember in new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" })
        {
            Assert.False(key.TryGetProperty(privateMember, out _), $"JWKS exposes private parameter '{privateMember}'");
        }

        // The key identifier is the one stored for the active signing key; the encryption key is not published.
        var stored = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ProtocolKeys.AsNoTracking().ToListAsync());
        Assert.Equal(stored.Single(x => x.Use == ProtocolKeyUse.Signing && x.Status == ProtocolKeyStatus.Active).Kid, key.GetProperty("kid").GetString());
        Assert.DoesNotContain(stored.Single(x => x.Use == ProtocolKeyUse.Encryption).Kid, jwks.GetRawText());

        // At rest the private key is wrapped: the column does not contain a PKCS#8 structure in clear.
        Assert.All(stored, row => Assert.NotEqual(0x30, row.ProtectedPrivateKey[0]));
    }

    [Fact]
    public async Task Code_WithPkce_IssuesOpaqueAccessTokenAndSignedIdToken()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var pkce = Pkce.Create();

        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, pkce, state: "st-42", nonce: "n-42"), user);
        Assert.NotNull(outcome.Code);
        Assert.Equal("st-42", outcome.State);
        Assert.StartsWith(client.RedirectUri, outcome.Redirect!.GetLeftPart(UriPartial.Path));
        Assert.Equal($"{Stack.IamOrigin}/", Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(outcome.Redirect.Query)["iss"].ToString());

        var tokens = await client.ExchangeCodeAsync(outcome.Code, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.Equal("Bearer", tokens.String("token_type"));
        Assert.InRange(tokens.Json.GetProperty("expires_in").GetInt32(), 295, 300);
        Assert.Equal("no-store", tokens.Raw.Headers.CacheControl?.ToString());

        // Access and refresh tokens are opaque references, not self-contained JWTs.
        Assert.DoesNotContain('.', tokens.AccessToken);
        Assert.DoesNotContain('.', tokens.RefreshToken);

        // The ID token is validated with the published JWKS by a JWT library (signature, issuer, audience, lifetime).
        var jwks = new JsonWebKeySet((await GetJsonAsync("/.well-known/jwks")).GetRawText());
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(tokens.IdToken, new TokenValidationParameters
        {
            ValidIssuer = $"{Stack.IamOrigin}/",
            ValidAudience = DemoCatalog.PanoClientId,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            LifetimeValidator = (notBefore, expires, _, _) => (notBefore is null || notBefore <= Stack.Time.GetUtcNow().UtcDateTime.AddMinutes(1)) && expires > Stack.Time.GetUtcNow().UtcDateTime,
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);
        var idToken = (JsonWebToken)validation.SecurityToken;
        Assert.Equal(user.Id.ToString(), idToken.Subject);
        Assert.Equal("n-42", idToken.GetClaim("nonce").Value);
        Assert.Equal(user.Email, idToken.GetClaim("email").Value);
        Assert.Equal(user.DisplayName, idToken.GetClaim("name").Value);
        Assert.Equal("pwd", idToken.GetClaim("amr").Value);
        Assert.InRange(long.Parse(idToken.GetClaim("auth_time").Value), Stack.Time.GetUtcNow().ToUnixTimeSeconds() - 5, Stack.Time.GetUtcNow().ToUnixTimeSeconds());
        Assert.True(idToken.TryGetClaim("at_hash", out _));
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type is "role" or "roles" or "scope");

        // The grant links the tokens to the central session that authenticated.
        var grant = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.SingleAsync(x => x.UserId == user.Id));
        var session = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.SingleAsync(x => x.UserId == user.Id));
        Assert.Equal(session.Id, grant.SessionId);
        Assert.Equal(DemoCatalog.PanoClientId, grant.ClientId);
        Assert.Null(grant.RevokedAt);
    }

    [Fact]
    public async Task Code_WrongOrMissingVerifier_IsRejected()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);

        var first = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create()), user);
        var wrong = await client.ExchangeCodeAsync(first.Code!, Pkce.Create().Verifier);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.Status);
        Assert.Equal("invalid_grant", wrong.Error);
        Assert.False(wrong.Has("access_token"));

        var second = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create()));
        var missing = await client.ExchangeCodeAsync(second.Code!, verifier: null);
        Assert.Equal(HttpStatusCode.BadRequest, missing.Status);
        Assert.Contains(missing.Error, new[] { "invalid_request", "invalid_grant" });
        Assert.False(missing.Has("access_token"));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("plain-text-challenge-value-that-is-long-enough-000", "plain")]
    public async Task Code_WithoutS256Challenge_IsRejectedAtTheAuthorizationEndpoint(string? challenge, string? method)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        await Stack.SignInAsync(browser, user);

        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, pkce: null, overrides: new Dictionary<string, string?>
        {
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = method,
        }));

        // OpenIddict reports request validation errors on its own page instead of redirecting them to the client.
        Assert.Null(outcome.Code);
        Assert.False(outcome.ReturnedToClient);
        Assert.Equal(HttpStatusCode.BadRequest, outcome.Page!.Status);
    }

    [Fact]
    public async Task Code_SecondUse_IsRejected_AndTheTokensOfTheFirstUseAreRevoked()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var pkce = Pkce.Create();
        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, pkce), user);
        var first = await client.ExchangeCodeAsync(outcome.Code!, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", first.AccessToken)).Status);

        var replay = await client.ExchangeCodeAsync(outcome.Code!, pkce.Verifier);

        Assert.Equal(HttpStatusCode.BadRequest, replay.Status);
        Assert.Equal("invalid_grant", replay.Error);

        // A replayed code is treated as an interception: everything issued from it stops working.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.ApiAsync(HttpMethod.Get, "/notes", first.AccessToken)).Status);
        Assert.Equal("invalid_grant", (await client.RefreshAsync(first.RefreshToken)).Error);
    }

    [Fact]
    public async Task Code_RedeemedByAnotherClient_OrWithWrongSecretOrRedirectUri_IsRejected()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);

        var pkce = Pkce.Create();
        var outcome = await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(PanoScopes, pkce), user);

        var wrongSecret = await pano.ExchangeCodeAsync(outcome.Code!, pkce.Verifier, secretOverride: "not-the-secret");
        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecret.Status);
        Assert.Equal("invalid_client", wrongSecret.Error);

        var otherClient = await rapor.ExchangeCodeAsync(outcome.Code!, pkce.Verifier, redirectUriOverride: pano.RedirectUri);
        Assert.Equal(HttpStatusCode.BadRequest, otherClient.Status);
        Assert.Equal("invalid_grant", otherClient.Error);

        var pkce2 = Pkce.Create();
        var second = await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(PanoScopes, pkce2));
        var wrongRedirect = await pano.ExchangeCodeAsync(second.Code!, pkce2.Verifier, redirectUriOverride: $"{Stack.PanoOrigin}/other-callback");
        Assert.Equal(HttpStatusCode.BadRequest, wrongRedirect.Status);
        Assert.Equal("invalid_grant", wrongRedirect.Error);
    }

    public static TheoryData<string> UnregisteredRedirects() =>
    [
        "{pano}/signin-oidc/extra",
        "{pano}/signin-oidc?next=1",
        "{pano}/signin-oidc/",
        "{pano}/Signin-Oidc",
        "{pano}/",
        "{pano}.evil.example/signin-oidc",
        "https://evil.example/signin-oidc",
        "{panoHttp}/signin-oidc",
        "{pano}/signin-oidc#fragment",
        "{pano}/signin-oidc/../signin-oidc",
        "{rapor}/signin-oidc",
    ];

    [Theory]
    [MemberData(nameof(UnregisteredRedirects))]
    public async Task Redirect_AnythingButTheExactRegisteredUri_IsRefusedWithoutRedirecting(string template)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        await Stack.SignInAsync(browser, user);
        var redirect = template
            .Replace("{panoHttp}", Stack.PanoOrigin.Replace("https://", "http://", StringComparison.Ordinal), StringComparison.Ordinal)
            .Replace("{pano}", Stack.PanoOrigin, StringComparison.Ordinal)
            .Replace("{rapor}", Stack.RaporOrigin, StringComparison.Ordinal);

        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create(), overrides: new Dictionary<string, string?> { ["redirect_uri"] = redirect }));

        // The browser is never sent to the unregistered address: the error is shown by the identity provider itself.
        Assert.False(outcome.ReturnedToClient);
        Assert.Equal(HttpStatusCode.BadRequest, outcome.Page!.Status);
        Assert.Null(outcome.Page.Response.Headers.Location);
    }

    [Theory]
    [InlineData("openid workspace.write", "rapor")]
    [InlineData("openid email", "rapor")]
    [InlineData("openid workspace.jobs", "pano")]
    [InlineData("openid does.not.exist", "pano")]
    public async Task Client_CannotObtainAScopeItIsNotAllowed(string scope, string which)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = which == "rapor" ? ProtocolClient.Rapor(Stack) : ProtocolClient.Pano(Stack);
        await Stack.SignInAsync(browser, user);

        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(scope, Pkce.Create()));

        Assert.Null(outcome.Code);
        Assert.False(outcome.ReturnedToClient);
        Assert.Equal(HttpStatusCode.BadRequest, outcome.Page!.Status);
        Assert.Equal(0, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.CountAsync(x => x.UserId == user.Id)));
    }

    [Theory]
    [InlineData("token")]
    [InlineData("id_token")]
    [InlineData("code id_token")]
    [InlineData("code token")]
    public async Task Client_ImplicitAndHybridResponseTypes_AreRefused(string responseType)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        await Stack.SignInAsync(browser, user);

        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create(), overrides: new Dictionary<string, string?> { ["response_type"] = responseType }));

        Assert.Null(outcome.Code);
        var body = outcome.Page?.Body ?? string.Empty;
        Assert.True(outcome.Error is "unsupported_response_type" or "unauthorized_client" or "invalid_request" || outcome.Page?.Status == HttpStatusCode.BadRequest, body);
        Assert.DoesNotContain("access_token=", outcome.Redirect?.ToString() ?? string.Empty);
        Assert.DoesNotContain("id_token=", outcome.Redirect?.ToString() ?? string.Empty);
    }

    [Fact]
    public async Task Token_PasswordGrantAndUnknownClient_AreRefusedWithStandardOAuthErrors()
    {
        var user = await Stack.CreateUserAsync();
        using var client = ProtocolClient.Pano(Stack);

        var password = await client.PostAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = user.Email,
            ["password"] = user.Password,
            ["scope"] = "openid",
        }, client.ClientId, client.ClientSecret);
        Assert.Equal(HttpStatusCode.BadRequest, password.Status);
        Assert.Equal("unsupported_grant_type", password.Error);
        Assert.Equal("application/json", password.Raw.Content.Headers.ContentType?.MediaType);

        var unknown = await client.PostAsync("/connect/token", new Dictionary<string, string> { ["grant_type"] = "client_credentials" }, "no-such-client", "whatever");
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.Status);
        Assert.Equal("invalid_client", unknown.Error);
        Assert.False(unknown.Has("title"), "protocol errors must not be converted to ProblemDetails");
    }
}
