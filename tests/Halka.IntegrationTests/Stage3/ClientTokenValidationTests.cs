using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Halka.DemoClient;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Halka.IntegrationTests.Stage3;

/// <summary>
/// Rewrites the ID token in token responses on their way to Pano's OpenID Connect handler. Only the transport is
/// intercepted: the handler and its validation library run unchanged and must reject every manipulation.
/// </summary>
public sealed class IdTokenTamper
{
    public Func<string, string>? Rewrite { get; set; }

    public int Rewritten { get; private set; }

    public sealed class Handler(HttpMessageHandler inner, IdTokenTamper tamper) : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            if (tamper.Rewrite is not { } rewrite || request.RequestUri?.AbsolutePath != "/connect/token" || !response.IsSuccessStatusCode)
            {
                return response;
            }

            var json = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
            if (json["id_token"]?.GetValue<string>() is { } original)
            {
                json["id_token"] = rewrite(original);
                tamper.Rewritten++;
                response.Content = new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
            }

            return response;
        }
    }
}

public sealed class TamperFixture : StackFixture
{
    public IdTokenTamper Tamper { get; } = new();

    protected override StackOptions Options
    {
        get
        {
            var options = new StackOptions();
            options.ConfigureClient = (slug, builder) =>
            {
                if (slug != "pano")
                {
                    return;
                }

                // Registered last, so it replaces the back-channel client the handler created from its own settings.
                builder.Services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>>(new PostConfigureOptions<OpenIdConnectOptions>(
                    DemoClientHost.OidcScheme,
                    oidc => oidc.Backchannel = new HttpClient(new IdTokenTamper.Handler(oidc.BackchannelHttpHandler!, Tamper)) { Timeout = oidc.BackchannelTimeout }));
            };
            return options;
        }
    }
}

[CollectionDefinition(Name)]
public sealed class TamperCollection : ICollectionFixture<TamperFixture>
{
    public const string Name = "tamper";
}

[Collection(TamperCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class ClientTokenValidationTests(TamperFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private static string Encode(JsonNode node) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(node.ToJsonString()));

    private static JsonObject Decode(string segment) => JsonNode.Parse(Base64Url.DecodeFromChars(segment))!.AsObject();

    private async Task<(Page Landing, int Sessions)> SignInWithAsync(Func<string, string>? rewrite)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var before = fixture.Tamper.Rewritten;
        fixture.Tamper.Rewrite = rewrite;
        try
        {
            var landing = await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
            if (rewrite is not null)
            {
                Assert.Equal(before + 1, fixture.Tamper.Rewritten);
                Assert.Null(browser.Cookie(Stack.PanoOrigin, "__Host-pano-session"));
            }

            await using var scope = Stack.Pano.Services.CreateAsyncScope();
            var sessions = await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.CountAsync(x => x.Subject == user.Id.ToString());
            return (landing, sessions);
        }
        finally
        {
            fixture.Tamper.Rewrite = null;
        }
    }

    private static void AssertRejected((Page Landing, int Sessions) result)
    {
        Assert.Equal("/signin-problem", result.Landing.Url.AbsolutePath);
        Assert.Equal("Not signed in to Pano", ClientFlow.Badge(result.Landing));
        Assert.Equal(0, result.Sessions);
    }

    [Fact]
    public async Task Control_UntamperedResponse_SignsIn()
    {
        var result = await SignInWithAsync(null);

        Assert.Equal("/workspace", result.Landing.Url.AbsolutePath);
        Assert.Equal(1, result.Sessions);
    }

    [Fact]
    public async Task IdToken_WithModifiedSignature_IsRejected()
        => AssertRejected(await SignInWithAsync(token =>
        {
            var parts = token.Split('.');
            var signature = Base64Url.DecodeFromChars(parts[2]);
            signature[0] ^= 0xFF;
            return $"{parts[0]}.{parts[1]}.{Base64Url.EncodeToString(signature)}";
        }));

    [Fact]
    public async Task IdToken_WithModifiedPayload_IsRejected()
        => AssertRejected(await SignInWithAsync(token =>
        {
            var parts = token.Split('.');
            var payload = Decode(parts[1]);
            payload["sub"] = Guid.NewGuid().ToString();
            return $"{parts[0]}.{Encode(payload)}.{parts[2]}";
        }));

    [Fact]
    public async Task IdToken_WithAlgNone_IsRejected()
        => AssertRejected(await SignInWithAsync(token =>
        {
            var parts = token.Split('.');
            var header = Decode(parts[0]);
            header["alg"] = "none";
            return $"{Encode(header)}.{parts[1]}.";
        }));

    [Fact]
    public async Task IdToken_SignedByAnotherKey_WithTheSameKeyId_OrAnotherIssuer_IsRejected()
    {
        using var attackerKey = RSA.Create(2048);
        string Resign(string token, Action<JsonObject> change)
        {
            var parts = token.Split('.');
            var header = Decode(parts[0]);
            var payload = Decode(parts[1]);
            change(payload);
            var signingInput = $"{Encode(header)}.{Encode(payload)}";
            var signature = attackerKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
        }

        AssertRejected(await SignInWithAsync(token => Resign(token, _ => { })));
        AssertRejected(await SignInWithAsync(token => Resign(token, payload => payload["iss"] = "https://evil.example/")));
    }

    [Fact]
    public async Task IdToken_IssuedForAnotherClient_IsRejected_WrongAudience()
    {
        // A genuine ID token of the real issuer with a valid signature, but issued to Rapor.
        var other = await Stack.CreateUserAsync();
        using var otherBrowser = Stack.NewBrowser();
        using var rapor = ProtocolClient.Rapor(Stack);
        var foreign = (await rapor.SignInAsync(otherBrowser, other, "openid profile")).IdToken;
        Assert.Contains(new JsonWebToken(foreign).Audiences, audience => audience == "rapor-web");

        AssertRejected(await SignInWithAsync(_ => foreign));
    }

    [Fact]
    public async Task IdToken_FromAnotherAuthorizationRequest_IsRejected_NonceMismatch()
    {
        // A genuine ID token for Pano itself (right issuer, audience and signature) that belongs to a different
        // authorization request, so its nonce is not the one bound to this browser.
        var other = await Stack.CreateUserAsync();
        using var otherBrowser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var foreign = (await pano.SignInAsync(otherBrowser, other, "openid profile")).IdToken;
        Assert.Contains(new JsonWebToken(foreign).Audiences, audience => audience == "pano-web");

        AssertRejected(await SignInWithAsync(_ => foreign));
    }
}

/// <summary>The identity provider's clock is eleven minutes behind: every ID token it issues is already expired.</summary>
public sealed class ExpiredTokenFixture : StackFixture
{
    protected override StackOptions Options => new() { IamClockOffset = TimeSpan.FromMinutes(-11) };
}

[CollectionDefinition(Name)]
public sealed class ExpiredTokenCollection : ICollectionFixture<ExpiredTokenFixture>
{
    public const string Name = "expired-token";
}

[Collection(ExpiredTokenCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class ExpiredIdTokenTests(ExpiredTokenFixture fixture)
{
    [Fact]
    public async Task IdToken_Expired_IsRejectedByTheClient()
    {
        var stack = fixture.Stack;
        var user = await stack.CreateUserAsync();
        using var browser = stack.NewBrowser();

        // The token is genuine (right issuer, audience, signature and nonce) but its lifetime ended six minutes
        // ago, beyond the validator's five minute clock skew.
        var landing = await ClientFlow.SignInAsync(stack, browser, stack.PanoOrigin, user);

        Assert.Equal("/signin-problem", landing.Url.AbsolutePath);
        Assert.Null(browser.Cookie(stack.PanoOrigin, "__Host-pano-session"));
        await using var scope = stack.Pano.Services.CreateAsyncScope();
        Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.CountAsync());
    }
}
