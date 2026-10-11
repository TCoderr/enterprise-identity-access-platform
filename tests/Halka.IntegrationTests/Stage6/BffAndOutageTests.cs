using System.Net;
using Halka.DemoClient;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Halka.IntegrationTests.Stage6;

/// <summary>Demo clients refresh when a token has less than 285 of its 300 seconds left, so small clock steps trigger it.</summary>
public sealed class BffFixture : StackFixture
{
    protected override StackOptions Options
    {
        get
        {
            var options = new StackOptions();
            options.ClientSettings["Client:RefreshSkewSeconds"] = "285";
            return options;
        }
    }
}

[CollectionDefinition(Name)]
public sealed class BffCollection : ICollectionFixture<BffFixture>
{
    public const string Name = "bff";
}

[Collection(BffCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class BffTests(BffFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private async Task<(AppSession Row, StoredSession Session)> PanoSessionAsync(Guid userId)
    {
        await using var scope = Stack.Pano.Services.CreateAsyncScope();
        var row = await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.AsNoTracking().SingleAsync(x => x.Subject == userId.ToString());
        return (row, (await scope.ServiceProvider.GetRequiredService<AppSessionStore>().FindAsync(row.Id, CancellationToken.None))!);
    }

    private async Task<int> PanoSessionCountAsync(Guid userId)
    {
        await using var scope = Stack.Pano.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<ClientDbContext>().AppSessions.CountAsync(x => x.Subject == userId.ToString());
    }

    [Fact]
    public async Task Bff_ConcurrentRequests_RefreshOnce_SingleFlight_AndNeverLookLikeTokenReuse()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        var before = await PanoSessionAsync(user.Id);
        Assert.Equal(1, before.Row.Version);

        // The access token is now inside the refresh window. Eight requests of the same browser arrive together.
        Stack.Time.Advance(TimeSpan.FromSeconds(20));
        var pages = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => browser.GetAsync($"{Stack.PanoOrigin}/workspace")));

        Assert.All(pages, page =>
        {
            Assert.Equal(HttpStatusCode.OK, page.Status);
            Assert.Equal("Signed in to Pano", ClientFlow.Badge(page));
        });

        // Exactly one refresh happened: one version step, one redeemed refresh token, one new one, grant intact.
        var after = await PanoSessionAsync(user.Id);
        Assert.Equal(2, after.Row.Version);
        Assert.NotEqual(before.Session.Tokens.AccessToken, after.Session.Tokens.AccessToken);
        var grant = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.AsNoTracking().SingleAsync(x => x.UserId == user.Id));
        Assert.Null(grant.RevokedAt);
        var refreshTokens = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Tokens.AsNoTracking()
            .Where(x => x.Authorization!.Id == grant.AuthorizationId && x.Type == OpenIddictConstants.TokenTypeIdentifiers.RefreshToken)
            .Select(x => x.Status).ToListAsync());
        Assert.Equal(2, refreshTokens.Count);
        Assert.Single(refreshTokens, status => status == OpenIddictConstants.Statuses.Redeemed);
        Assert.Single(refreshTokens, status => status == OpenIddictConstants.Statuses.Valid);
        Assert.Equal(0, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents.CountAsync(x => x.TargetId == grant.AuthorizationId.ToString() && x.Reason!.StartsWith(RevocationReason.RefreshReuse))));

        // The refreshed token works against the API.
        var loaded = await ClientFlow.WorkspaceAsync(browser, pages[0], "Load");
        Assert.Equal("200", ClientFlow.ApiStatus(loaded));
    }

    [Fact]
    public async Task Bff_ManualRefresh_ReplacesTheTokens()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        var before = await PanoSessionAsync(user.Id);

        var session = await browser.GetAsync($"{Stack.PanoOrigin}/session");
        var refreshed = await browser.SubmitAsync(session, "form[action*='handler=Refresh']");

        Assert.Equal("/session", refreshed.Url.AbsolutePath);
        Assert.Contains("Tokens were refreshed", refreshed.Text);
        var after = await PanoSessionAsync(user.Id);
        Assert.Equal(before.Row.Version + 1, after.Row.Version);
        Assert.NotEqual(before.Session.Tokens.RefreshToken, after.Session.Tokens.RefreshToken);
        Assert.DoesNotContain(after.Session.Tokens.AccessToken, refreshed.Body);
    }

    [Fact]
    public async Task Bff_GrantRevokedAtTheProvider_EndsTheApplicationSessionOnTheNextRequest()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        using var captured = browser.CloneWithCookies();
        var grant = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.AsNoTracking().SingleAsync(x => x.UserId == user.Id));

        await Stack.InIamAsync(services => services.GetRequiredService<RevocationService>()
            .RevokeGrantAsync(grant.AuthorizationId, RevocationReason.AdminRevoked, AuditActor.System, null, CancellationToken.None));

        // No cache: the very next request of the application notices.
        var home = await browser.GetAsync($"{Stack.PanoOrigin}/");
        Assert.Equal("Not signed in to Pano", ClientFlow.Badge(home));
        Assert.Equal(0, await PanoSessionCountAsync(user.Id));
        Assert.Equal("Not signed in to Pano", ClientFlow.Badge(await captured.GetAsync($"{Stack.PanoOrigin}/")));

        // The central session still exists, so signing in to Pano again is silent.
        var again = await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user: null);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(again));
    }

    [Fact]
    public async Task Bff_LocalLogout_RevokesItsOwnTokensAtTheProvider_AndKeepsTheCentralSession()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        using var captured = browser.CloneWithCookies();
        var tokens = (await PanoSessionAsync(user.Id)).Session.Tokens;
        using var pano = ProtocolClient.Pano(Stack);
        Assert.True((await pano.IntrospectAsync(tokens.AccessToken)).Json.GetProperty("active").GetBoolean());

        var session = await browser.GetAsync($"{Stack.PanoOrigin}/session");
        var signedOut = await browser.SubmitAsync(session, "form[action*='handler=Local']", follow: false);
        Assert.Equal(HttpStatusCode.Redirect, signedOut.Status);
        var landing = await browser.GetAsync(new Uri(new Uri(Stack.PanoOrigin), signedOut.Response.Headers.Location!).ToString());
        Assert.Equal("\"cache\"", landing.Header("Clear-Site-Data"));
        Assert.Contains("Pano only", landing.Text);

        // The application's tokens were revoked at the provider, the server-side session is gone, and a copy of
        // the application cookie no longer signs anyone in.
        Assert.False((await pano.IntrospectAsync(tokens.AccessToken)).Json.GetProperty("active").GetBoolean());
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(tokens.RefreshToken!)).Error);
        Assert.Equal(0, await PanoSessionCountAsync(user.Id));
        Assert.Equal("Not signed in to Pano", ClientFlow.Badge(await captured.GetAsync($"{Stack.PanoOrigin}/")));

        // The provider session is untouched: this is not a global logout.
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
    }

    [Fact]
    public async Task Bff_SignInAgainFresh_ForcesCredentialsAtTheProvider_AndReportsANewAuthenticationTime()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        var session = await browser.GetAsync($"{Stack.PanoOrigin}/session");
        var firstAuthTime = session.Find("time")!.GetAttribute("datetime");
        Stack.Time.Advance(TimeSpan.FromSeconds(3));

        // The provider must show its sign-in form even though the browser has a valid central session.
        var atProvider = await browser.SubmitAsync(session, "form[action*='handler=Fresh']");
        Assert.Equal(new Uri(Stack.IamOrigin).Authority, atProvider.Url.Authority);
        Assert.True(ClientFlow.IsLoginPage(atProvider));

        var back = await ClientFlow.ContinueAsync(Stack, browser, atProvider, user);
        Assert.Equal(new Uri(Stack.PanoOrigin).Authority, back.Url.Authority);
        Assert.Equal("/session", back.Url.AbsolutePath);
        Assert.NotEqual(firstAuthTime, back.Find("time")!.GetAttribute("datetime"));
    }
}

public sealed class OutageFixture : StackFixture;

[CollectionDefinition(Name)]
public sealed class OutageCollection : ICollectionFixture<OutageFixture>
{
    public const string Name = "outage";
}

[Collection(OutageCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class OutageTests(OutageFixture fixture)
{
    private const string Scopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Outage_IdentityProviderDown_ApiAndBffFailClosed_ThenRecoverWithTheSameTokensAndKeys()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        var tokens = await client.SignInAsync(browser, user, Scopes);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        var kidBefore = System.Text.Json.JsonDocument.Parse((await browser.GetAsync($"{Stack.IamOrigin}/.well-known/jwks")).Body)
            .RootElement.GetProperty("keys")[0].GetProperty("kid").GetString();

        await Stack.StopIamAsync();
        try
        {
            // API: a token that was valid a moment ago cannot be verified. That is neither success nor "invalid token".
            var api = await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, api.Status);
            Assert.Equal("5", api.Raw.Headers.RetryAfter?.ToString());
            Assert.EndsWith("/authorization-server-unavailable", api.String("type"));
            Assert.False(api.Raw.Headers.WwwAuthenticate.Any(), "an unverifiable token must not be reported as invalid");
            Assert.NotEqual(System.Text.Json.JsonValueKind.Array, api.Json.ValueKind);

            // A request without any token needs no verification and is still a plain 401.
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.ApiAsync(HttpMethod.Get, "/notes", bearer: null)).Status);

            // BFF: the application session cannot be confirmed. No protected content, and the cookie is kept.
            var workspace = await browser.GetAsync($"{Stack.PanoOrigin}/workspace");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, workspace.Status);
            Assert.Contains("could not be verified", workspace.Text);
            Assert.DoesNotContain(user.DisplayName, workspace.Body);
            Assert.DoesNotContain("Load notes", workspace.Body);
            Assert.NotNull(browser.Cookie(Stack.PanoOrigin, "__Host-pano-session"));
        }
        finally
        {
            await Stack.StartIamAsync();
        }

        // Recovery without re-authentication: token state, sessions and signing keys were persisted.
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        var recovered = await browser.GetAsync($"{Stack.PanoOrigin}/workspace");
        Assert.Equal(HttpStatusCode.OK, recovered.Status);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(recovered));
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        var kidAfter = System.Text.Json.JsonDocument.Parse((await browser.GetAsync($"{Stack.IamOrigin}/.well-known/jwks")).Body)
            .RootElement.GetProperty("keys")[0].GetProperty("kid").GetString();
        Assert.Equal(kidBefore, kidAfter);
        Assert.Equal(HttpStatusCode.OK, (await client.RefreshAsync(tokens.RefreshToken)).Status);

        // A revocation issued after the restart is honoured, so the persisted state is really authoritative.
        await Stack.InIamAsync(services => services.GetRequiredService<RevocationService>()
            .RevokeUserClientGrantsAsync(user.Id, DemoCatalog.PanoClientId, RevocationReason.AdminRevoked, AuditActor.System, null, CancellationToken.None));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
    }
}
