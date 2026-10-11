using System.Net;
using Halka.DemoClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.IntegrationTests.Stage3;

/// <summary>End-to-end through the real ASP.NET Core OpenID Connect middleware of the Pano relying party.</summary>
[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class RealClientTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private async Task<int> PanoSessionCountAsync(Guid userId)
    {
        await using var scope = Stack.Pano.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.CountAsync(x => x.Subject == userId.ToString());
    }

    [Fact]
    public async Task Pano_SignInThroughTheIdentityProvider_ThenCallsTheApi()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();

        var landing = await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);

        Assert.Equal(new Uri(Stack.PanoOrigin).Authority, landing.Url.Authority);
        Assert.Equal("/workspace", landing.Url.AbsolutePath);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(landing));
        Assert.Contains(user.DisplayName, landing.Text);

        var added = await ClientFlow.WorkspaceAsync(browser, landing, "Add", new Dictionary<string, string> { ["NoteText"] = "note from pano" });
        Assert.Equal("201", ClientFlow.ApiStatus(added));
        var loaded = await ClientFlow.WorkspaceAsync(browser, added, "Load");
        Assert.Equal("200", ClientFlow.ApiStatus(loaded));
        Assert.Contains("note from pano", loaded.Text);

        // The application cookie is a host-only, secure, HTTP-only cookie of the Pano origin only.
        var cookie = browser.Cookie(Stack.PanoOrigin, "__Host-pano-session")!;
        Assert.True(cookie.Secure);
        Assert.True(cookie.HttpOnly);
        Assert.Null(browser.Cookie(Stack.RaporOrigin, "__Host-pano-session"));
        Assert.Null(browser.Cookie(Stack.IamOrigin, "__Host-pano-session"));

        // Tokens stay on the server: no response of the application ever contained one, and the session page shows none.
        var session = await browser.GetAsync($"{Stack.PanoOrigin}/session");
        Assert.Equal(HttpStatusCode.OK, session.Status);
        Assert.Contains("workspace.write", session.Text);
        Assert.Contains("no-store", session.Header("Cache-Control"));
        await using var scope = Stack.Pano.Services.CreateAsyncScope();
        var stored = await scope.ServiceProvider.GetRequiredService<AppSessionStore>().FindAsync(
            (await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.SingleAsync(x => x.Subject == user.Id.ToString())).Id, CancellationToken.None);
        foreach (var page in new[] { landing, added, loaded, session })
        {
            Assert.DoesNotContain(stored!.Tokens.AccessToken, page.Body);
            Assert.DoesNotContain(stored.Tokens.RefreshToken!, page.Body);
            Assert.DoesNotContain(stored.Tokens.IdToken!, page.Body);
        }

        Assert.DoesNotContain(stored!.Tokens.AccessToken, cookie.Value);

        // At rest the tokens are encrypted.
        var raw = await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.AsNoTracking().SingleAsync(x => x.Subject == user.Id.ToString());
        Assert.DoesNotContain(stored.Tokens.AccessToken, System.Text.Encoding.UTF8.GetString(raw.ProtectedTokens));
    }

    [Fact]
    public async Task Pano_ProtectedPages_RequireSignIn_AndAnonymousHomeIsPublic()
    {
        using var browser = Stack.NewBrowser();

        var home = await browser.GetAsync($"{Stack.PanoOrigin}/");
        var workspace = await browser.GetAsync($"{Stack.PanoOrigin}/workspace", follow: false);

        Assert.Equal(HttpStatusCode.OK, home.Status);
        Assert.Equal("Not signed in to Pano", ClientFlow.Badge(home));
        Assert.Equal(HttpStatusCode.Redirect, workspace.Status);
        Assert.StartsWith($"{Stack.IamOrigin}/connect/authorize", workspace.Response.Headers.Location!.ToString());
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(workspace.Response.Headers.Location!.Query);
        Assert.Equal("code", query["response_type"].ToString());
        Assert.Equal("S256", query["code_challenge_method"].ToString());
        Assert.False(string.IsNullOrEmpty(query["code_challenge"]));
        Assert.False(string.IsNullOrEmpty(query["state"]));
        Assert.False(string.IsNullOrEmpty(query["nonce"]));
        Assert.False(query.ContainsKey("response_mode") && query["response_mode"] == "fragment");
    }

    [Fact]
    public async Task Pano_Callback_WithoutState_WithForeignState_OrReplayed_IsRejectedByTheClient()
    {
        var user = await Stack.CreateUserAsync();
        using var victim = Stack.NewBrowser();
        using var attacker = Stack.NewBrowser();

        // No state at all.
        var noState = await victim.GetAsync($"{Stack.PanoOrigin}/signin-oidc?code=anything");
        Assert.Equal("/signin-problem", noState.Url.AbsolutePath);

        // The attacker completes a sign-in up to the point where the provider redirects back, and plants that
        // callback URL (attacker's code and state) into the victim's browser: login CSRF / session swapping.
        await Stack.SignInAsync(attacker, user);
        var challenge = await attacker.GetAsync($"{Stack.PanoOrigin}/login", follow: false);
        var authorize = await attacker.GetAsync(challenge.Response.Headers.Location!.ToString(), follow: false);
        var consent = await ClientFlow.ContinueAsync(Stack, attacker, authorize, null, consent: null);
        var callback = await attacker.SubmitAsync(consent, "form[action='/connect/authorize']", new Dictionary<string, string> { ["consent_decision"] = "allow" }, follow: false);
        var callbackUrl = callback.Response.Headers.Location!.ToString();
        Assert.StartsWith($"{Stack.PanoOrigin}/signin-oidc?code=", callbackUrl);

        var planted = await victim.GetAsync(callbackUrl);
        Assert.Equal("/signin-problem", planted.Url.AbsolutePath);
        Assert.Null(victim.Cookie(Stack.PanoOrigin, "__Host-pano-session"));

        // In the attacker's own browser the same URL works once and is refused when replayed.
        var first = await attacker.GetAsync(callbackUrl);
        Assert.Equal("/workspace", first.Url.AbsolutePath);
        var replay = await attacker.GetAsync(callbackUrl);
        Assert.Equal("/signin-problem", replay.Url.AbsolutePath);
        Assert.Equal(1, await PanoSessionCountAsync(user.Id));
    }

    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    [InlineData("/\\evil.example/")]
    public async Task Pano_LoginReturnUrl_OnlyAcceptsLocalPaths(string returnUrl)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();

        var landing = await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user, path: $"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");

        Assert.Equal(new Uri(Stack.PanoOrigin).Authority, landing.Url.Authority);
        Assert.Equal("/workspace", landing.Url.AbsolutePath);
        Assert.DoesNotContain(landing.Visited, uri => uri.Host.Contains("evil", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Pano_MutationsRequireAnAntiForgeryToken()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);

        var forgedNote = await browser.PostFormAsync($"{Stack.PanoOrigin}/workspace?handler=Add", [new("NoteText", "forged")]);
        var forgedLogout = await browser.PostFormAsync($"{Stack.PanoOrigin}/logout?handler=Global", []);

        Assert.Equal(HttpStatusCode.BadRequest, forgedNote.Status);
        Assert.Equal(HttpStatusCode.BadRequest, forgedLogout.Status);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(await browser.GetAsync($"{Stack.PanoOrigin}/")));
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class CodeExpiryTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Code_Expired_IsRejected()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var pkce = Pkce.Create();
        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl("openid profile offline_access workspace.read", pkce), user);
        Assert.NotNull(outcome.Code);

        // Codes live for two minutes.
        Stack.Time.Advance(TimeSpan.FromMinutes(2) + TimeSpan.FromSeconds(1));
        var late = await client.ExchangeCodeAsync(outcome.Code, pkce.Verifier);

        Assert.Equal(HttpStatusCode.BadRequest, late.Status);
        Assert.Equal("invalid_grant", late.Error);
        Assert.False(late.Has("access_token"));
    }

    [Fact]
    public async Task AccessToken_Expired_IsRejectedByTheApi_AndRefreshIssuesAWorkingOne()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var tokens = await client.SignInAsync(browser, user, "openid offline_access workspace.read");
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);

        Stack.Time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        var refreshed = await client.RefreshAsync(tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", refreshed.AccessToken)).Status);
    }
}
