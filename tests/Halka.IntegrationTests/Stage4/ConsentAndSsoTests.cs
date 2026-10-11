using System.Net;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Protocol;
using Halka.Iam.Sessions;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Halka.IntegrationTests.Stage4;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class ConsentAndSsoTests(StackFixture fixture)
{
    private const string PanoScopes = "openid profile email offline_access workspace.read workspace.write";
    private const string RaporScopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    private Task<int> GrantCountAsync(Guid userId, string clientId)
        => Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.CountAsync(x => x.UserId == userId && x.ClientId == clientId));

    [Fact]
    public async Task Sso_SignedInToPano_ThenRapor_NeedsNoCredentials_ButStillAsksForRaporsConsent()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var pano = await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(pano));

        // Rapor starts its own authorization request. The browser already has a central session.
        var atProvider = await ClientFlow.SignInAsync(Stack, browser, Stack.RaporOrigin, user: null, consent: null);

        Assert.Equal(new Uri(Stack.IamOrigin).Authority, atProvider.Url.Authority);
        Assert.False(ClientFlow.IsLoginPage(atProvider), "single sign-on must not ask for credentials again");
        Assert.True(ClientFlow.IsConsentPage(atProvider), "consent is per application and must still be requested");
        Assert.DoesNotContain(atProvider.Visited, uri => uri.AbsolutePath == "/account/login");
        Assert.Contains("Rapor", atProvider.Find("h1 + p")!.TextContent);
        Assert.Contains("rapor-web", atProvider.Text);
        Assert.Contains(user.Email, atProvider.Text);
        var requested = atProvider.Document.QuerySelectorAll(".scope-list li strong").Select(item => item.TextContent).ToList();
        Assert.Contains("Read workspace notes", requested);
        Assert.DoesNotContain("Add workspace notes", requested);
        Assert.DoesNotContain("Read your e-mail address", requested);

        var rapor = await ClientFlow.ContinueAsync(Stack, browser, atProvider, user: null);
        Assert.Equal(new Uri(Stack.RaporOrigin).Authority, rapor.Url.Authority);
        Assert.Equal("Signed in to Rapor", ClientFlow.Badge(rapor));

        // Two relying parties, two separate application sessions, one central session, two grants.
        Assert.NotNull(browser.Cookie(Stack.PanoOrigin, "__Host-pano-session"));
        Assert.NotNull(browser.Cookie(Stack.RaporOrigin, "__Host-rapor-session"));
        Assert.NotEqual(browser.Cookie(Stack.PanoOrigin, "__Host-pano-session")!.Value, browser.Cookie(Stack.RaporOrigin, "__Host-rapor-session")!.Value);
        var grants = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.Where(x => x.UserId == user.Id).ToListAsync());
        Assert.Equal(2, grants.Count);
        Assert.Single(grants.Select(grant => grant.SessionId).Distinct());
        Assert.Equal(["pano-web", "rapor-web"], grants.Select(grant => grant.ClientId).Order());

        // Rapor can read but its token cannot write.
        var read = await ClientFlow.WorkspaceAsync(browser, rapor, "Load");
        Assert.Equal("200", ClientFlow.ApiStatus(read));
        var write = await ClientFlow.WorkspaceAsync(browser, read, "Add", new Dictionary<string, string> { ["NoteText"] = "rapor tries to write" });
        Assert.Equal("403", ClientFlow.ApiStatus(write));
        Assert.Contains("Insufficient scope", write.Text);

        // Signing out of Rapor only does not touch Pano or the central session.
        var rapSession = await browser.GetAsync($"{Stack.RaporOrigin}/session");
        var signedOut = await browser.SubmitAsync(rapSession, "form[action*='handler=Local']");
        Assert.Equal("/signed-out", signedOut.Url.AbsolutePath);
        Assert.Equal("Not signed in to Rapor", ClientFlow.Badge(await browser.GetAsync($"{Stack.RaporOrigin}/")));
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(await browser.GetAsync($"{Stack.PanoOrigin}/")));
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
    }

    [Fact]
    public async Task Consent_Denied_ReturnsAccessDenied_AndCreatesNoGrant()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Rapor(Stack);

        var outcome = await client.AuthorizeAsync(browser, client.AuthorizeUrl(RaporScopes, Pkce.Create(), state: "keep-me"), user, consent: "deny");

        Assert.Null(outcome.Code);
        Assert.Equal("access_denied", outcome.Error);
        Assert.Equal("keep-me", outcome.State);
        Assert.Equal(0, await GrantCountAsync(user.Id, DemoCatalog.RaporClientId));
        Assert.False(await Stack.InIamAsync(services => services.GetRequiredService<ConsentService>().CoversAsync(user.Id, DemoCatalog.RaporClientId, ["openid"], CancellationToken.None)));

        // Through the real client the user ends on an explanatory page and is not signed in.
        using var second = Stack.NewBrowser();
        var landing = await ClientFlow.SignInAsync(Stack, second, Stack.RaporOrigin, user, consent: "deny");
        Assert.Equal("/signin-problem", landing.Url.AbsolutePath);
        Assert.Contains("did not allow", landing.Text);
        Assert.Null(second.Cookie(Stack.RaporOrigin, "__Host-rapor-session"));
    }

    [Fact]
    public async Task Consent_IsRemembered_AskedAgainForNewScopes_AndForPromptConsent()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);

        var first = await client.AuthorizeAsync(browser, client.AuthorizeUrl("openid profile", Pkce.Create()), user);
        Assert.NotNull(first.Code);

        // Same scopes: no consent screen (the helper would stop on it because it is told not to answer).
        var remembered = await client.AuthorizeAsync(browser, client.AuthorizeUrl("openid profile", Pkce.Create()), consent: null);
        Assert.NotNull(remembered.Code);

        // A broader request needs a new decision.
        var broader = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create()), consent: null);
        Assert.Null(broader.Code);
        Assert.True(ClientFlow.IsConsentPage(broader.Page!));

        // prompt=consent always asks.
        var forced = await client.AuthorizeAsync(browser, client.AuthorizeUrl("openid profile", Pkce.Create(), overrides: new Dictionary<string, string?> { ["prompt"] = "consent" }), consent: null);
        Assert.Null(forced.Code);
        Assert.True(ClientFlow.IsConsentPage(forced.Page!));
    }

    [Fact]
    public async Task Consent_ForgedDecision_WithoutOrWithForeignAntiForgeryToken_GrantsNothing()
    {
        var victim = await Stack.CreateUserAsync();
        var attackerUser = await Stack.CreateUserAsync();
        using var victimBrowser = Stack.NewBrowser();
        using var attackerBrowser = Stack.NewBrowser();
        using var client = ProtocolClient.Rapor(Stack);
        await Stack.SignInAsync(victimBrowser, victim);
        await Stack.SignInAsync(attackerBrowser, attackerUser);
        var pkce = Pkce.Create();
        var parameters = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(client.AuthorizeUrl(RaporScopes, pkce)).Query)
            .Select(pair => new KeyValuePair<string, string>(pair.Key, pair.Value.ToString()))
            .Append(new("consent_decision", "allow"))
            .ToList();

        // 1. Cross-site form post: the victim's cookies are attached but there is no token.
        var withoutToken = await victimBrowser.PostFormAsync($"{Stack.IamOrigin}/connect/authorize", parameters, follow: false);
        Assert.Equal(HttpStatusCode.BadRequest, withoutToken.Status);

        // 2. The attacker obtains a genuine consent form for their own session and replays its token for the victim.
        var attackerConsent = await client.AuthorizeAsync(attackerBrowser, client.AuthorizeUrl(RaporScopes, pkce), consent: null);
        var foreignToken = attackerConsent.Page!.Find("form[action='/connect/authorize'] input[name=__RequestVerificationToken]")!.GetAttribute("value")!;
        var withForeignToken = await victimBrowser.PostFormAsync($"{Stack.IamOrigin}/connect/authorize",
            parameters.Append(new("__RequestVerificationToken", foreignToken)), follow: false);
        Assert.Equal(HttpStatusCode.BadRequest, withForeignToken.Status);

        Assert.Equal(0, await GrantCountAsync(victim.Id, DemoCatalog.RaporClientId));
        Assert.False(await Stack.InIamAsync(services => services.GetRequiredService<ConsentService>().CoversAsync(victim.Id, DemoCatalog.RaporClientId, ["openid"], CancellationToken.None)));

        // A GET with the decision in the query string is not a decision either: the consent screen is shown.
        var viaGet = await victimBrowser.GetAsync(client.AuthorizeUrl(RaporScopes, pkce) + "&consent_decision=allow", follow: false);
        Assert.Equal(HttpStatusCode.OK, viaGet.Status);
        Assert.True(ClientFlow.IsConsentPage(viaGet));
        Assert.Equal(0, await GrantCountAsync(victim.Id, DemoCatalog.RaporClientId));
    }

    [Fact]
    public async Task Prompt_None_ReturnsLoginRequired_ConsentRequired_OrACode()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Rapor(Stack);
        var none = new Dictionary<string, string?> { ["prompt"] = "none" };

        var anonymous = await client.AuthorizeAsync(browser, client.AuthorizeUrl(RaporScopes, Pkce.Create(), state: "s1", overrides: none));
        Assert.Equal("login_required", anonymous.Error);
        Assert.Equal("s1", anonymous.State);
        Assert.DoesNotContain(anonymous.Redirect!.Query, "code=");

        await Stack.SignInAsync(browser, user);
        var noConsent = await client.AuthorizeAsync(browser, client.AuthorizeUrl(RaporScopes, Pkce.Create(), overrides: none));
        Assert.Equal("consent_required", noConsent.Error);

        Assert.NotNull((await client.AuthorizeAsync(browser, client.AuthorizeUrl(RaporScopes, Pkce.Create()))).Code);
        var silent = await client.AuthorizeAsync(browser, client.AuthorizeUrl(RaporScopes, Pkce.Create(), overrides: none), consent: null);
        Assert.NotNull(silent.Code);
        Assert.Null(silent.Error);
    }

    [Fact]
    public async Task Prompt_Login_CannotBeSatisfiedByAnExistingSsoCookie()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var first = await client.SignInAsync(browser, user, PanoScopes);
        var firstAuthTime = long.Parse(new JsonWebToken(first.IdToken).GetClaim("auth_time").Value);
        var originalSession = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.SingleAsync(x => x.UserId == user.Id));

        Stack.Time.Advance(TimeSpan.FromSeconds(2));
        var pkce = Pkce.Create();
        var url = client.AuthorizeUrl(PanoScopes, pkce, overrides: new Dictionary<string, string?> { ["prompt"] = "login" });

        // The provider shows the sign-in form although a valid session exists.
        var challenged = await client.AuthorizeAsync(browser, url, user: null, consent: null);
        Assert.Null(challenged.Code);
        Assert.True(ClientFlow.IsLoginPage(challenged.Page!));
        Assert.Contains("sign in again", challenged.Page!.Text);

        // Navigating to the same request again, or replaying it with a copy of the cookies, still does not issue a code.
        var again = await client.AuthorizeAsync(browser, url, user: null, consent: null);
        Assert.Null(again.Code);
        Assert.True(ClientFlow.IsLoginPage(again.Page!));
        using var copied = browser.CloneWithCookies();
        var replay = await client.AuthorizeAsync(copied, url, user: null, consent: null);
        Assert.Null(replay.Code);

        // Only real credentials continue the request; the result reports the new authentication time.
        var completed = await client.AuthorizeAsync(browser, url, user);
        Assert.NotNull(completed.Code);
        var tokens = await client.ExchangeCodeAsync(completed.Code, pkce.Verifier);
        var authTime = long.Parse(new JsonWebToken(tokens.IdToken).GetClaim("auth_time").Value);
        Assert.True(authTime >= firstAuthTime + 2, $"auth_time {authTime} must be newer than {firstAuthTime}");

        var sessions = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.Where(x => x.UserId == user.Id).OrderBy(x => x.CreatedAt).ToListAsync());
        Assert.Equal(2, sessions.Count);
        Assert.Equal(originalSession.Id, sessions[0].Id);
        Assert.Equal(SessionEndReason.Replaced, sessions[0].RevokedReason);
        Assert.Null(sessions[1].RevokedAt);

        // The same request cannot be reused afterwards without authenticating again.
        var later = await client.AuthorizeAsync(browser, url, user: null, consent: null);
        Assert.Null(later.Code);
        Assert.True(ClientFlow.IsLoginPage(later.Page!));
    }

    [Fact]
    public async Task UserInfo_AndIdToken_OnlyContainClaimsOfGrantedScopes()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);

        var full = await pano.SignInAsync(browser, user, PanoScopes);
        var fullInfo = await pano.UserInfoAsync(full.AccessToken);
        Assert.Equal(HttpStatusCode.OK, fullInfo.Status);
        Assert.Equal(user.Id.ToString(), fullInfo.String("sub"));
        Assert.Equal(user.DisplayName, fullInfo.String("name"));
        Assert.Equal(user.Email, fullInfo.String("email"));
        Assert.True(fullInfo.Json.GetProperty("email_verified").GetBoolean());

        // Rapor is not allowed the e-mail scope: neither its ID token nor UserInfo reveals the address.
        var limited = await rapor.SignInAsync(browser, user, RaporScopes);
        var limitedInfo = await rapor.UserInfoAsync(limited.AccessToken);
        Assert.Equal(user.DisplayName, limitedInfo.String("name"));
        Assert.Equal(user.Email, limitedInfo.String("preferred_username"));
        Assert.False(limitedInfo.Has("email"));
        Assert.False(limitedInfo.Has("email_verified"));
        var limitedIdToken = new JsonWebToken(limited.IdToken);
        Assert.False(limitedIdToken.TryGetClaim("email", out _));
        Assert.True(limitedIdToken.TryGetClaim("name", out _));

        // Without the profile scope only the subject is returned.
        var minimal = await pano.SignInAsync(browser, user, "openid");
        var minimalInfo = await pano.UserInfoAsync(minimal.AccessToken);
        Assert.Equal(["sub"], minimalInfo.Json.EnumerateObject().Select(property => property.Name));
        var minimalIdToken = new JsonWebToken(minimal.IdToken);
        Assert.False(minimalIdToken.TryGetClaim("name", out _));
        Assert.False(minimalIdToken.TryGetClaim("email", out _));

        // UserInfo needs a valid access token; an ID token or nothing is refused with a Bearer challenge.
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.UserInfoAsync(full.IdToken)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.UserInfoAsync("garbage")).Status);
    }

    [Fact]
    public async Task Consent_Revoked_KillsTheClientsTokensImmediately_AndConsentIsAskedAgain()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        var panoTokens = await pano.SignInAsync(browser, user, PanoScopes);
        var raporTokens = await rapor.SignInAsync(browser, user, RaporScopes);

        var revoked = await Stack.InIamAsync(services => services.GetRequiredService<ConsentService>()
            .RevokeAsync(user.Id, DemoCatalog.PanoClientId, AuditActor.User, user.Id.ToString(), CancellationToken.None));
        Assert.True(revoked);

        // Pano: access, refresh and userinfo stop at once. Rapor and the central session are untouched.
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", panoTokens.AccessToken)).Status);
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(panoTokens.RefreshToken)).Error);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.UserInfoAsync(panoTokens.AccessToken)).Status);
        Assert.Equal(HttpStatusCode.OK, (await rapor.ApiAsync(HttpMethod.Get, "/notes", raporTokens.AccessToken)).Status);
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        var next = await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(PanoScopes, Pkce.Create()), consent: null);
        Assert.Null(next.Code);
        Assert.True(ClientFlow.IsConsentPage(next.Page!));
    }

    [Fact]
    public async Task ClientSecrets_AreStoredHashed_AndNeverExposedByPublicEndpoints()
    {
        var secrets = new[] { Stack.Demo.PanoSecret, Stack.Demo.RaporSecret, Stack.Demo.WorkspaceApiSecret, Stack.Demo.OpsMachineSecret };
        var stored = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Applications.AsNoTracking().Select(x => x.ClientSecret).ToListAsync());
        Assert.True(stored.Count >= 4, "the four demo clients are registered (other tests may add temporary ones)");
        Assert.All(stored, hash => Assert.DoesNotContain(hash, secrets));
        Assert.All(stored, hash => Assert.True(hash!.Length > 40));

        using var browser = Stack.NewBrowser();
        foreach (var path in new[] { "/.well-known/openid-configuration", "/.well-known/jwks", "/openapi/v1.json", "/account/login" })
        {
            var body = (await browser.GetAsync($"{Stack.IamOrigin}{path}")).Body;
            Assert.All(secrets, secret => Assert.DoesNotContain(secret, body));
            Assert.All(stored, hash => Assert.DoesNotContain(hash!, body));
        }
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class MaxAgeTests(StackFixture fixture)
{
    private const string Scopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task MaxAge_OlderSession_MustAuthenticateAgain_AndAuthTimeIsReported()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Rapor(Stack);
        var first = await client.SignInAsync(browser, user, Scopes);
        var firstAuthTime = long.Parse(new JsonWebToken(first.IdToken).GetClaim("auth_time").Value);

        Stack.Time.Advance(TimeSpan.FromMinutes(3));

        // Recent enough for max_age=600: silent single sign-on, same authentication time.
        var pkce = Pkce.Create();
        var withinLimit = await client.AuthorizeAsync(browser, client.AuthorizeUrl(Scopes, pkce, overrides: new Dictionary<string, string?> { ["max_age"] = "600" }), consent: null);
        Assert.NotNull(withinLimit.Code);
        var sameSession = await client.ExchangeCodeAsync(withinLimit.Code, pkce.Verifier);
        Assert.Equal(firstAuthTime, long.Parse(new JsonWebToken(sameSession.IdToken).GetClaim("auth_time").Value));

        // Too old for max_age=60: prompt=none fails, an interactive request shows the sign-in form.
        var silent = await client.AuthorizeAsync(browser, client.AuthorizeUrl(Scopes, Pkce.Create(), overrides: new Dictionary<string, string?> { ["max_age"] = "60", ["prompt"] = "none" }));
        Assert.Equal("login_required", silent.Error);

        var pkce2 = Pkce.Create();
        var url = client.AuthorizeUrl(Scopes, pkce2, overrides: new Dictionary<string, string?> { ["max_age"] = "60" });
        var interactive = await client.AuthorizeAsync(browser, url, user: null, consent: null);
        Assert.Null(interactive.Code);
        Assert.True(ClientFlow.IsLoginPage(interactive.Page!));

        var completed = await client.AuthorizeAsync(browser, url, user);
        var fresh = await client.ExchangeCodeAsync(completed.Code!, pkce2.Verifier);
        Assert.Equal(firstAuthTime + 180, long.Parse(new JsonWebToken(fresh.IdToken).GetClaim("auth_time").Value));

        // max_age=0 behaves like prompt=login even though the session was created a moment ago.
        var zero = await client.AuthorizeAsync(browser, client.AuthorizeUrl(Scopes, Pkce.Create(), overrides: new Dictionary<string, string?> { ["max_age"] = "0" }), user: null, consent: null);
        Assert.Null(zero.Code);
        Assert.True(ClientFlow.IsLoginPage(zero.Page!));
    }
}
