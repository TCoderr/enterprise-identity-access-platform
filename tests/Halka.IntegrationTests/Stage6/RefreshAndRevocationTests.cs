using System.Net;
using Halka.Iam.Admin;
using Halka.Iam.Audit;
using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Halka.IntegrationTests.Stage6;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class RefreshAndRevocationTests(StackFixture fixture)
{
    private const string PanoScopes = "openid profile email offline_access workspace.read workspace.write";
    private const string RaporScopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    private Task<SessionGrant> GrantAsync(Guid userId, string clientId)
        => Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.AsNoTracking().SingleAsync(x => x.UserId == userId && x.ClientId == clientId));

    private async Task<bool> ApiAcceptsAsync(ProtocolClient client, string accessToken)
        => (await client.ApiAsync(HttpMethod.Get, "/notes", accessToken)).Status == HttpStatusCode.OK;

    private async Task<bool> IntrospectsActiveAsync(string token)
    {
        using var api = new ProtocolClient(Stack, DemoCatalog.WorkspaceApiClientId, Stack.Demo.WorkspaceApiSecret, string.Empty);
        return (await api.IntrospectAsync(token)).Json.GetProperty("active").GetBoolean();
    }

    [Fact]
    public async Task Refresh_Rotates_TheOldRefreshTokenIsDead_AndAccessTokensKeepWorking()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var first = await client.SignInAsync(browser, user, PanoScopes);

        var second = await client.RefreshAsync(first.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.NotEqual(first.AccessToken, second.AccessToken);
        Assert.True(await ApiAcceptsAsync(client, second.AccessToken));
        Assert.True(second.Has("id_token"));

        // The grant, and with it the session binding, is unchanged by a normal rotation.
        var grant = await GrantAsync(user.Id, DemoCatalog.PanoClientId);
        Assert.Null(grant.RevokedAt);
        var third = await client.RefreshAsync(second.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, third.Status);
        Assert.True(await ApiAcceptsAsync(client, third.AccessToken));
    }

    [Fact]
    public async Task Refresh_ReuseOfARotatedToken_RevokesTheWholeFamilyAndTheGrant()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var first = await client.SignInAsync(browser, user, PanoScopes);
        var second = await client.RefreshAsync(first.RefreshToken);
        Assert.True(await ApiAcceptsAsync(client, second.AccessToken));

        // Someone presents the already rotated token again (the thief or the legitimate client, it cannot be told).
        var reuse = await client.RefreshAsync(first.RefreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, reuse.Status);
        Assert.Equal("invalid_grant", reuse.Error);
        Assert.False(reuse.Has("access_token"));

        // Everything descended from the grant is dead immediately: the newest refresh token and both access tokens.
        Assert.Equal("invalid_grant", (await client.RefreshAsync(second.RefreshToken)).Error);
        Assert.False(await ApiAcceptsAsync(client, first.AccessToken));
        Assert.False(await ApiAcceptsAsync(client, second.AccessToken));
        Assert.False(await IntrospectsActiveAsync(second.AccessToken));

        var grant = await GrantAsync(user.Id, DemoCatalog.PanoClientId);
        Assert.NotNull(grant.RevokedAt);
        Assert.Equal(RevocationReason.RefreshReuse, grant.RevokedReason);
        var audit = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents.AsNoTracking()
            .Where(x => x.Action == "grant.revoked" && x.TargetId == grant.AuthorizationId.ToString()).ToListAsync());
        Assert.Contains(audit, entry => entry.Reason!.StartsWith(RevocationReason.RefreshReuse, StringComparison.Ordinal));

        // The central session is not affected: the user can authorise again without credentials.
        var again = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create()), consent: null);
        Assert.NotNull(again.Code);
    }

    [Fact]
    public async Task Refresh_ParallelUseOfTheSameToken_RotatesExactlyOnce_AndTheFamilyEndsRevoked()
    {
        // Six clients present the same refresh token; a barrier releases them together. The race is repeated so
        // that different interleavings are exercised; the assertions are invariants that hold for every one of them.
        const int parallel = 6;
        const int rounds = 10;
        var clients = Enumerable.Range(0, parallel).Select(_ => ProtocolClient.Pano(Stack)).ToList();
        using var client = ProtocolClient.Pano(Stack);
        try
        {
            for (var round = 0; round < rounds; round++)
            {
                var user = await Stack.CreateUserAsync();
                using var browser = Stack.NewBrowser();
                var tokens = await client.SignInAsync(browser, user, PanoScopes);
                using var barrier = new Barrier(parallel);
                var responses = await Task.WhenAll(clients.Select(racer => Task.Run(async () =>
                {
                    barrier.SignalAndWait(TimeSpan.FromSeconds(10));
                    return await racer.RefreshAsync(tokens.RefreshToken);
                })));
                var summary = string.Join(", ", responses.Select(response => $"{(int)response.Status} {response.Error}"));

                // 1. Exactly one request rotates the token; every other answer is the standard invalid_grant error.
                var succeeded = responses.Where(response => response.Status == HttpStatusCode.OK).ToList();
                Assert.True(succeeded.Count == 1, summary);
                Assert.All(responses.Except(succeeded), response => Assert.True(response.Status == HttpStatusCode.BadRequest && response.Error == "invalid_grant", summary));

                // 2. Policy: a second presentation of a refresh token is a compromise signal even when it is
                //    concurrent. The grant and its authorization entry are revoked.
                var grant = await GrantAsync(user.Id, DemoCatalog.PanoClientId);
                Assert.NotNull(grant.RevokedAt);
                Assert.Equal(RevocationReason.RefreshReuse, grant.RevokedReason);
                var authorizationStatus = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Authorizations.AsNoTracking()
                    .Where(x => x.Id == grant.AuthorizationId).Select(x => x.Status).SingleAsync());
                Assert.Equal(OpenIddictConstants.Statuses.Revoked, authorizationStatus);

                // 3. Nothing of the family is usable: the original tokens and whatever the single winner received.
                Assert.False(await ApiAcceptsAsync(client, tokens.AccessToken));
                Assert.Equal("invalid_grant", (await client.RefreshAsync(tokens.RefreshToken)).Error);
                foreach (var winner in succeeded)
                {
                    Assert.Equal("invalid_grant", (await client.RefreshAsync(winner.RefreshToken)).Error);
                    Assert.False(await ApiAcceptsAsync(client, winner.AccessToken));
                    Assert.False(await IntrospectsActiveAsync(winner.AccessToken));
                    Assert.False((await client.IntrospectAsync(winner.RefreshToken, "refresh_token")).Json.GetProperty("active").GetBoolean());
                }

                // 4. The central session is unaffected; the user can authorise again silently.
                Assert.NotNull((await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create()), consent: null)).Code);
            }
        }
        finally
        {
            clients.ForEach(racer => racer.Dispose());
        }
    }

    [Fact]
    public async Task Refresh_CannotBeUsedByAnotherClient_OrToWidenScopes()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        var raporTokens = await rapor.SignInAsync(browser, user, RaporScopes);

        var stolenByPano = await pano.RefreshAsync(raporTokens.RefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, stolenByPano.Status);
        Assert.Equal("invalid_grant", stolenByPano.Error);

        var widened = await rapor.RefreshAsync(raporTokens.RefreshToken, scope: "openid workspace.read workspace.write");
        Assert.NotEqual(HttpStatusCode.OK, widened.Status);
        Assert.False(widened.Has("access_token"));
    }

    [Fact]
    public async Task Revocation_Endpoint_RevokesOwnTokens_AndGivesNothingAwayAboutOthers()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        var panoTokens = await pano.SignInAsync(browser, user, PanoScopes);

        // Another client "revoking" Pano's token, an unknown token and a wrong secret.
        var foreign = await rapor.RevokeAsync(panoTokens.RefreshToken, "refresh_token");
        var unknown = await pano.RevokeAsync("no-such-token");
        var badSecret = await pano.RevokeAsync(panoTokens.RefreshToken, secretOverride: "wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, badSecret.Status);
        Assert.Equal("invalid_client", badSecret.Error);
        Assert.NotEqual(HttpStatusCode.InternalServerError, foreign.Status);
        Assert.Equal(HttpStatusCode.OK, unknown.Status);
        Assert.True(await ApiAcceptsAsync(pano, panoTokens.AccessToken));
        Assert.True(await IntrospectsActiveAsync(panoTokens.AccessToken));

        // The owner revokes its access token: the API refuses it at once, the refresh token still works.
        Assert.Equal(HttpStatusCode.OK, (await pano.RevokeAsync(panoTokens.AccessToken, "access_token")).Status);
        Assert.False(await ApiAcceptsAsync(pano, panoTokens.AccessToken));
        var refreshed = await pano.RefreshAsync(panoTokens.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);

        // Revoking the refresh token ends the ability to continue.
        Assert.Equal(HttpStatusCode.OK, (await pano.RevokeAsync(refreshed.RefreshToken, "refresh_token")).Status);
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(refreshed.RefreshToken)).Error);
    }

    [Fact]
    public async Task Revoke_Grant_DeniesTheApiImmediately_OtherClientAndSessionUnaffected()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        var panoTokens = await pano.SignInAsync(browser, user, PanoScopes);
        var raporTokens = await rapor.SignInAsync(browser, user, RaporScopes);
        var grant = await GrantAsync(user.Id, DemoCatalog.PanoClientId);

        var revoked = await Stack.InIamAsync(services => services.GetRequiredService<RevocationService>()
            .RevokeGrantAsync(grant.AuthorizationId, RevocationReason.AdminRevoked, AuditActor.System, null, CancellationToken.None));

        Assert.Equal(1, revoked);
        Assert.False(await ApiAcceptsAsync(pano, panoTokens.AccessToken));
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(panoTokens.RefreshToken)).Error);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.UserInfoAsync(panoTokens.AccessToken)).Status);
        Assert.True(await ApiAcceptsAsync(rapor, raporTokens.AccessToken));
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // Consent was not withdrawn, so a new authorization is silent.
        Assert.NotNull((await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(PanoScopes, Pkce.Create()), consent: null)).Code);
    }

    [Fact]
    public async Task Revoke_UserDisabled_EndsSessionsAndTokensAtOnce_AndBlocksEveryWayBackIn()
    {
        var admin = await Stack.CreateUserAsync(Roles.SecurityAdmin);
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        var panoTokens = await pano.SignInAsync(browser, user, PanoScopes);
        var raporTokens = await rapor.SignInAsync(browser, user, RaporScopes);

        var result = await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetDisabledAsync(user.Id, true, admin.Id, CancellationToken.None));
        Assert.True(result.Succeeded);

        Assert.False(await ApiAcceptsAsync(pano, panoTokens.AccessToken));
        Assert.False(await ApiAcceptsAsync(rapor, raporTokens.AccessToken));
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(panoTokens.RefreshToken)).Error);
        Assert.Equal("invalid_grant", (await rapor.RefreshAsync(raporTokens.RefreshToken)).Error);
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        var silent = await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(PanoScopes, Pkce.Create(), overrides: new Dictionary<string, string?> { ["prompt"] = "none" }));
        Assert.Equal("login_required", silent.Error);
        Assert.Equal("/account/login", (await Stack.SignInAsync(browser, user)).Url.AbsolutePath);

        var sessions = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.AsNoTracking().Where(x => x.UserId == user.Id).ToListAsync());
        Assert.All(sessions, session => Assert.Equal(SessionEndReason.UserDisabled, session.RevokedReason));

        // Re-enabling does not resurrect anything that was revoked.
        Assert.True((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetDisabledAsync(user.Id, false, admin.Id, CancellationToken.None))).Succeeded);
        Assert.False(await ApiAcceptsAsync(pano, panoTokens.AccessToken));
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(panoTokens.RefreshToken)).Error);
        Assert.Equal("/manage", (await Stack.SignInAsync(browser, user)).Url.AbsolutePath);
    }

    [Fact]
    public async Task Revoke_ClientDisabled_KillsItsTokensAndBlocksAllOfItsEndpoints_OtherClientsContinue()
    {
        // A dedicated client so the shared demo clients stay enabled for other tests.
        var clientId = $"temp-web-{Guid.NewGuid():N}"[..24];
        var redirect = $"{Stack.PanoOrigin}/temp-callback";
        var secret = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().CreateAsync(
            new ClientRegistration(clientId, "Temporary", ClientKind.Web, [redirect], [], ["openid", "profile", "offline_access", "workspace.read"], OpenIddictConstants.ConsentTypes.Implicit),
            secret: null, actorId: null, CancellationToken.None));
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var temp = new ProtocolClient(Stack, clientId, secret, redirect);
        using var rapor = ProtocolClient.Rapor(Stack);
        var tokens = await temp.SignInAsync(browser, user, "openid profile offline_access workspace.read");
        var raporTokens = await rapor.SignInAsync(browser, user, RaporScopes);
        Assert.True(await ApiAcceptsAsync(temp, tokens.AccessToken));

        await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().SetDisabledAsync(clientId, true, null, CancellationToken.None));

        Assert.False(await ApiAcceptsAsync(temp, tokens.AccessToken));
        var refresh = await temp.RefreshAsync(tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.Status);
        Assert.Equal("invalid_client", refresh.Error);
        Assert.Equal(HttpStatusCode.Unauthorized, (await temp.IntrospectAsync(tokens.AccessToken)).Status);
        var authorize = await temp.AuthorizeAsync(browser, temp.AuthorizeUrl("openid profile", Pkce.Create()), consent: null);
        Assert.Null(authorize.Code);
        Assert.Equal("unauthorized_client", authorize.Error);
        Assert.True(await ApiAcceptsAsync(rapor, raporTokens.AccessToken));
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // Enabling it again does not bring the old tokens back; a new authorization works.
        await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().SetDisabledAsync(clientId, false, null, CancellationToken.None));
        Assert.False(await ApiAcceptsAsync(temp, tokens.AccessToken));
        Assert.NotEqual(HttpStatusCode.OK, (await temp.RefreshAsync(tokens.RefreshToken)).Status);
        Assert.NotNull((await temp.AuthorizeAsync(browser, temp.AuthorizeUrl("openid profile", Pkce.Create()), consent: null)).Code);
    }

    [Fact]
    public async Task GlobalLogout_EndsEveryApplicationSession_CapturedCookiesOfBothAppsAndTheProviderAreDenied()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        await ClientFlow.SignInAsync(Stack, browser, Stack.RaporOrigin, user: null);
        Assert.Equal("Signed in to Rapor", ClientFlow.Badge(await browser.GetAsync($"{Stack.RaporOrigin}/")));

        // The attacker copied all cookies (provider, Pano, Rapor) before the user signed out.
        using var attacker = browser.CloneWithCookies();
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(await attacker.GetAsync($"{Stack.PanoOrigin}/")));

        // "Sign out everywhere" from Pano: RP-initiated end session with confirmation at the provider.
        var session = await browser.GetAsync($"{Stack.PanoOrigin}/session");
        var confirm = await browser.SubmitAsync(session, "form[action*='handler=Global']");
        Assert.Equal(new Uri(Stack.IamOrigin).Authority, confirm.Url.Authority);
        Assert.Equal("/connect/endsession", confirm.Url.AbsolutePath);
        var done = await browser.SubmitAsync(confirm, "form[action='/connect/endsession']", new Dictionary<string, string> { ["logout_decision"] = "confirm" });
        Assert.Equal(new Uri(Stack.PanoOrigin).Authority, done.Url.Authority);
        Assert.Equal("/signed-out", done.Url.AbsolutePath);

        // Rapor was never told. It finds out on its next request because its token is no longer active.
        foreach (var agent in new[] { browser, attacker })
        {
            Assert.Equal("Not signed in to Pano", ClientFlow.Badge(await agent.GetAsync($"{Stack.PanoOrigin}/")));
            Assert.Equal("Not signed in to Rapor", ClientFlow.Badge(await agent.GetAsync($"{Stack.RaporOrigin}/")));
            Assert.Equal("/account/login", (await agent.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
            var workspace = await agent.GetAsync($"{Stack.RaporOrigin}/workspace", follow: false);
            Assert.Equal(HttpStatusCode.Redirect, workspace.Status);
        }

        // No redirect loop: asking Rapor to sign in again lands on the provider's sign-in form.
        var relogin = await ClientFlow.SignInAsync(Stack, browser, Stack.RaporOrigin, user: null);
        Assert.True(ClientFlow.IsLoginPage(relogin));
        Assert.True(relogin.Visited.Count < 6);

        var grants = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.AsNoTracking().Where(x => x.UserId == user.Id).ToListAsync());
        Assert.Equal(2, grants.Count);
        Assert.All(grants, grant => Assert.Equal(RevocationReason.SessionEnded, grant.RevokedReason));
    }

    [Fact]
    public async Task EndSession_ForgedRedirect_IsRefused_AndLogoutNeedsAConfirmedPost()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, PanoScopes);
        var hint = Uri.EscapeDataString(tokens.IdToken);

        // 1. An unregistered post-logout target is refused by the provider and never followed.
        foreach (var target in new[] { "https://evil.example/", $"{Stack.PanoOrigin}/other", $"{Stack.PanoOrigin}/signout-callback-oidc/extra", $"{Stack.RaporOrigin}/signout-callback-oidc" })
        {
            var forged = await browser.GetAsync($"{Stack.IamOrigin}/connect/endsession?id_token_hint={hint}&post_logout_redirect_uri={Uri.EscapeDataString(target)}&state=x", follow: false);
            Assert.Equal(HttpStatusCode.BadRequest, forged.Status);
            Assert.Null(forged.Response.Headers.Location);
        }

        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // 2. A plain link (GET) to the end-session endpoint only shows the confirmation; it does not sign out.
        var registered = Uri.EscapeDataString($"{Stack.PanoOrigin}/signout-callback-oidc");
        var page = await browser.GetAsync($"{Stack.IamOrigin}/connect/endsession?id_token_hint={hint}&post_logout_redirect_uri={registered}&state=abc", follow: false);
        Assert.Equal(HttpStatusCode.OK, page.Status);
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // 3. A cross-site POST with the decision but without the anti-forgery token is rejected.
        var forgedPost = await browser.PostFormAsync($"{Stack.IamOrigin}/connect/endsession",
            [new("id_token_hint", tokens.IdToken), new("post_logout_redirect_uri", $"{Stack.PanoOrigin}/signout-callback-oidc"), new("logout_decision", "confirm")], follow: false);
        Assert.Equal(HttpStatusCode.BadRequest, forgedPost.Status);
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // 4. The confirmed request signs out and returns to the registered address with the state.
        var confirmed = await browser.SubmitAsync(page, "form[action='/connect/endsession']", new Dictionary<string, string> { ["logout_decision"] = "confirm" }, follow: false);
        Assert.Equal(HttpStatusCode.Redirect, confirmed.Status);
        var location = confirmed.Response.Headers.Location!.ToString();
        Assert.StartsWith($"{Stack.PanoOrigin}/signout-callback-oidc", location);
        Assert.Contains("state=abc", location);
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class SessionBoundTokenTests(StackFixture fixture)
{
    private const string Scopes = "openid offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Tokens_DoNotOutliveTheCentralSession_RefreshCountsAsActivity()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var tokens = await client.SignInAsync(browser, user, Scopes);

        // Using the application keeps the central session alive beyond the idle timeout of 60 minutes.
        for (var minutes = 0; minutes < 100; minutes += 50)
        {
            Stack.Time.Advance(TimeSpan.FromMinutes(50));
            tokens = await client.RefreshAsync(tokens.RefreshToken);
            Assert.Equal(HttpStatusCode.OK, tokens.Status);
        }

        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);

        // After a full idle period without any activity the session has ended: the access token is refused by
        // introspection even inside its own lifetime window, and the refresh token no longer works.
        Stack.Time.Advance(TimeSpan.FromMinutes(61));
        Assert.Equal("invalid_grant", (await client.RefreshAsync(tokens.RefreshToken)).Error);

        var second = await Stack.CreateUserAsync();
        using var secondBrowser = Stack.NewBrowser();
        var fresh = await client.SignInAsync(secondBrowser, second, Scopes);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", fresh.AccessToken)).Status);
        await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.Where(x => x.UserId == second.Id)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.AbsoluteExpiresAt, Stack.Time.GetUtcNow().AddMinutes(1))));
        Stack.Time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.ApiAsync(HttpMethod.Get, "/notes", fresh.AccessToken)).Status);
        Assert.Equal("invalid_grant", (await client.RefreshAsync(fresh.RefreshToken)).Error);
    }
}
