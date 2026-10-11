namespace Halka.E2E;

/// <summary>Real Chrome against four separate HTTPS origins on four different sites.</summary>
[Collection(BrowserCollection.Name)]
public sealed class SsoBrowserTests(BrowserFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Pano_Login_ThenApi_ThenRapor_SingleSignOn_InARealBrowser()
    {
        var user = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        session.Observe();
        var page = session.Page;

        // Pano: redirected to the identity provider, credentials, consent, back to Pano.
        await page.GotoAsync(Stack.PanoOrigin + "/");
        Assert.Equal("Not signed in to Pano", await session.BadgeAsync());
        await page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/account/login", StringComparison.Ordinal));
        await session.SignInAtProviderAsync(user);
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
        Assert.Contains("Pano", await page.Locator("h1 + p").InnerTextAsync());
        await session.AllowAsync();
        await page.WaitForURLAsync(Stack.PanoOrigin + "/workspace");
        Assert.Equal("Signed in to Pano", await session.BadgeAsync());

        // API call through the BFF.
        await page.GetByLabel("Note").FillAsync("written in a real browser");
        await page.GetByRole(AriaRole.Button, new() { Name = "Add note" }).ClickAsync();
        Assert.Equal("201", (await page.GetByTestId("api-status").InnerTextAsync()).Trim());
        await page.GetByRole(AriaRole.Button, new() { Name = "Load notes", Exact = true }).ClickAsync();
        await Assertions.Expect(page.GetByRole(AriaRole.Cell, new() { Name = "written in a real browser" }).First).ToBeVisibleAsync();

        // Rapor: a different origin and site. No credentials are requested; consent for Rapor is.
        await page.GotoAsync(Stack.RaporOrigin + "/");
        Assert.Equal("Not signed in to Rapor", await session.BadgeAsync());
        await page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
        Assert.Equal(0, await page.GetByLabel("Password").CountAsync());
        Assert.Contains("Rapor", await page.Locator("h1 + p").InnerTextAsync());
        await session.AllowAsync();
        await page.WaitForURLAsync(Stack.RaporOrigin + "/workspace");
        Assert.Equal("Signed in to Rapor", await session.BadgeAsync());

        // Rapor reads the note Pano wrote, and is refused when it tries to write.
        await page.GetByRole(AriaRole.Button, new() { Name = "Load notes", Exact = true }).ClickAsync();
        await Assertions.Expect(page.GetByRole(AriaRole.Cell, new() { Name = "written in a real browser" }).First).ToBeVisibleAsync();
        await page.GetByLabel("Note").FillAsync("rapor must not write");
        await page.GetByRole(AriaRole.Button, new() { Name = "Add note" }).ClickAsync();
        Assert.Equal("403", (await page.GetByTestId("api-status").InnerTextAsync()).Trim());

        // Cookies: each origin has its own host-only, Secure, HttpOnly session cookie; nothing is shared.
        var panoCookies = await session.CookiesAsync(Stack.PanoOrigin);
        var raporCookies = await session.CookiesAsync(Stack.RaporOrigin);
        var providerCookies = await session.CookiesAsync(Stack.IamOrigin);
        var panoSession = Assert.Single(panoCookies, cookie => cookie.Name == "__Host-pano-session");
        var raporSession = Assert.Single(raporCookies, cookie => cookie.Name == "__Host-rapor-session");
        var central = Assert.Single(providerCookies, cookie => cookie.Name == "__Host-halka-session");
        foreach (var cookie in new[] { panoSession, raporSession, central })
        {
            Assert.True(cookie.Secure);
            Assert.True(cookie.HttpOnly);
            Assert.Equal(SameSiteAttribute.Lax, cookie.SameSite);
            Assert.False(cookie.Domain.StartsWith('.'), "session cookies must be host-only");
        }

        Assert.DoesNotContain(panoCookies, cookie => cookie.Name.Contains("rapor", StringComparison.Ordinal) || cookie.Name.Contains("halka-session", StringComparison.Ordinal));
        Assert.DoesNotContain(raporCookies, cookie => cookie.Name.Contains("pano", StringComparison.Ordinal));

        // The one-time correlation and nonce cookies of the OIDC round trip are gone after sign-in.
        Assert.DoesNotContain(panoCookies.Concat(raporCookies), cookie => cookie.Name.Contains("Correlation", StringComparison.Ordinal) || cookie.Name.Contains("Nonce", StringComparison.Ordinal));

        // Nothing token-like is reachable from script: no web storage use, no readable session cookie.
        foreach (var origin in new[] { Stack.PanoOrigin, Stack.RaporOrigin, Stack.IamOrigin })
        {
            await page.GotoAsync(origin + "/");
            Assert.Equal(0, await page.EvaluateAsync<int>("() => window.localStorage.length + window.sessionStorage.length"));
            Assert.DoesNotContain("session", await page.EvaluateAsync<string>("() => document.cookie"));
        }

        Assert.Empty(session.Problems);
    }

    [Fact]
    public async Task Consent_Denied_InARealBrowser_ReturnsToTheApplicationWithoutASession()
    {
        var user = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        var page = session.Page;

        await session.SignInToAppAsync(Stack.RaporOrigin, user, allow: false);
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
        await page.GetByRole(AriaRole.Button, new() { Name = "Deny", Exact = true }).ClickAsync();

        await page.WaitForURLAsync(url => url.StartsWith(Stack.RaporOrigin + "/signin-problem", StringComparison.Ordinal));
        Assert.Contains("did not allow", await page.Locator("[role=alert]").InnerTextAsync());
        Assert.Equal("Not signed in to Rapor", await session.BadgeAsync());
        Assert.DoesNotContain(await session.CookiesAsync(Stack.RaporOrigin), cookie => cookie.Name == "__Host-rapor-session");
    }

    [Fact]
    public async Task SessionCookie_CopiedIntoAnotherBrowser_StopsWorkingAfterLogout()
    {
        var user = await Stack.CreateUserAsync();
        await using var owner = await fixture.NewSessionAsync();
        await using var thief = await fixture.NewSessionAsync();
        await owner.SignInToAppAsync(Stack.PanoOrigin, user);
        await owner.Page.WaitForURLAsync(Stack.PanoOrigin + "/workspace");

        // Every cookie of the owner's browser is copied into a second browser profile.
        var stolen = (await owner.Context.CookiesAsync()).Select(cookie => new Cookie
        {
            Name = cookie.Name,
            Value = cookie.Value,
            Domain = cookie.Domain,
            Path = cookie.Path,
            Secure = cookie.Secure,
            HttpOnly = cookie.HttpOnly,
            SameSite = cookie.SameSite,
        });
        await thief.Context.AddCookiesAsync(stolen);
        await thief.Page.GotoAsync(Stack.PanoOrigin + "/workspace");
        Assert.Equal("Signed in to Pano", await thief.BadgeAsync());

        // The owner signs out centrally (confirmation at the identity provider).
        await owner.Page.GotoAsync(Stack.PanoOrigin + "/session");
        await owner.Page.GetByRole(AriaRole.Button, new() { Name = "Sign out everywhere" }).ClickAsync();
        await owner.Page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/endsession", StringComparison.Ordinal));
        await owner.Page.GetByRole(AriaRole.Button, new() { Name = "Sign out of Halka ID", Exact = true }).ClickAsync();
        await owner.Page.WaitForURLAsync(url => url.StartsWith(Stack.PanoOrigin + "/signed-out", StringComparison.Ordinal));

        // The copied cookies are still present and unexpired in the second browser, but they open nothing.
        await thief.Page.GotoAsync(Stack.PanoOrigin + "/");
        Assert.Equal("Not signed in to Pano", await thief.BadgeAsync());
        await thief.Page.GotoAsync(Stack.IamOrigin + "/manage");
        Assert.StartsWith(Stack.IamOrigin + "/account/login", thief.Page.Url);
    }
}
