using HttpStatusCode = System.Net.HttpStatusCode;
using System.Text.RegularExpressions;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.E2E;

/// <summary>
/// Final-gate browser scenarios: second factor in the single sign-on chain, forced re-authentication, revocation
/// seen from both applications, client lifecycle through the administration UI and object-level authorization.
/// </summary>
[Collection(BrowserCollection.Name)]
public sealed class RevocationAndLifecycleBrowserTests(BrowserFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private static async Task<string> ApiStatusAsync(IPage page) => (await page.GetByTestId("api-status").InnerTextAsync()).Trim();

    private static async Task<BrowserSession> WithCopiedCookiesAsync(BrowserFixture fixture, BrowserSession source)
    {
        var copy = await fixture.NewSessionAsync();
        await copy.Context.AddCookiesAsync((await source.Context.CookiesAsync()).Select(cookie => new Cookie
        {
            Name = cookie.Name,
            Value = cookie.Value,
            Domain = cookie.Domain,
            Path = cookie.Path,
            Secure = cookie.Secure,
            HttpOnly = cookie.HttpOnly,
            SameSite = cookie.SameSite,
        }));
        return copy;
    }

    private async Task<string> BadgeAtAsync(BrowserSession session, string origin)
    {
        await session.Page.GotoAsync(origin + "/");
        return await session.BadgeAsync();
    }

    [Fact]
    public async Task Mfa_SignInAtPano_ThenSensitiveApi_ThenRaporSso_AndAFreshSignInAsksForBothFactorsAgain()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        await using var session = await fixture.NewSessionAsync();
        session.Observe();
        var page = session.Page;

        // Pano → provider: the password alone creates no session anywhere.
        await page.GotoAsync(Stack.PanoOrigin + "/");
        await page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/account/login", StringComparison.Ordinal));
        await session.SignInAtProviderAsync(account.User);
        await page.WaitForURLAsync(url => url.Contains("/account/mfa", StringComparison.Ordinal));
        Assert.DoesNotContain(await session.CookiesAsync(Stack.IamOrigin), cookie => cookie.Name == "__Host-halka-session");
        Assert.DoesNotContain(await session.CookiesAsync(Stack.PanoOrigin), cookie => cookie.Name == "__Host-pano-session");

        await page.GetByLabel("Authentication code").FillAsync(account.Device.NextCode());
        await page.GetByRole(AriaRole.Button, new() { Name = "Verify" }).ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
        await session.AllowAsync();
        await page.WaitForURLAsync(Stack.PanoOrigin + "/workspace");
        Assert.Equal("Signed in to Pano", await session.BadgeAsync());

        // The API endpoint that demands a multi-factor sign-in accepts this session's token.
        await page.GetByRole(AriaRole.Button, new() { Name = "Load sensitive notes" }).ClickAsync();
        Assert.Equal("200", await ApiStatusAsync(page));

        // Rapor: neither the password nor the code is asked again; Rapor's own consent is.
        await page.GotoAsync(Stack.RaporOrigin + "/");
        await page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
        Assert.Equal(0, await page.GetByLabel("Password").CountAsync());
        Assert.Equal(0, await page.GetByLabel("Authentication code").CountAsync());
        await session.AllowAsync();
        await page.WaitForURLAsync(Stack.RaporOrigin + "/workspace");
        await page.GetByRole(AriaRole.Button, new() { Name = "Load sensitive notes" }).ClickAsync();
        Assert.Equal("200", await ApiStatusAsync(page));

        // "Sign in again (fresh)" (prompt=login): the existing single sign-on session is not enough.
        await page.GotoAsync(Stack.PanoOrigin + "/session");
        var firstAuthTime = await page.Locator("time").First.GetAttributeAsync("datetime");
        Stack.Time.Advance(TimeSpan.FromSeconds(3));
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign in again (fresh)" }).ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/account/login", StringComparison.Ordinal));
        await Assertions.Expect(page.GetByLabel("Password")).ToBeVisibleAsync();
        await session.SignInAtProviderAsync(account.User);
        await page.WaitForURLAsync(url => url.Contains("/account/mfa", StringComparison.Ordinal));
        await page.GetByLabel("Authentication code").FillAsync(account.Device.NextCode());
        await page.GetByRole(AriaRole.Button, new() { Name = "Verify" }).ClickAsync();
        await page.WaitForURLAsync(Stack.PanoOrigin + "/session");
        Assert.NotEqual(firstAuthTime, await page.Locator("time").First.GetAttributeAsync("datetime"));

        Assert.Empty(session.Problems);
    }

    [Fact]
    public async Task Revocation_AtTheProvider_IsSeenByBothApplications_AndByCopiedCookies()
    {
        var user = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        var page = session.Page;
        await session.SignInToAppAsync(Stack.PanoOrigin, user);
        await page.WaitForURLAsync(Stack.PanoOrigin + "/workspace");
        await session.SignInToAppAsync(Stack.RaporOrigin, user: null);
        await page.WaitForURLAsync(Stack.RaporOrigin + "/workspace");

        // A second browser profile holds a copy of every cookie (provider, Pano, Rapor).
        await using var copied = await WithCopiedCookiesAsync(fixture, session);
        Assert.Equal("Signed in to Pano", await BadgeAtAsync(copied, Stack.PanoOrigin));

        // 1. Grant revocation: the user withdraws Pano's access at the provider.
        await page.GotoAsync(Stack.IamOrigin + "/manage/apps");
        await page.GetByRole(AriaRole.Button, new() { NameRegex = new Regex("Withdraw access.*Pano") }).ClickAsync();
        await page.WaitForLoadStateAsync();

        Assert.Equal("Not signed in to Pano", await BadgeAtAsync(session, Stack.PanoOrigin));
        Assert.Equal("Not signed in to Pano", await BadgeAtAsync(copied, Stack.PanoOrigin));

        // Rapor and its API access are untouched: this was one grant, not the session.
        await page.GotoAsync(Stack.RaporOrigin + "/workspace");
        await page.GetByRole(AriaRole.Button, new() { Name = "Load notes", Exact = true }).ClickAsync();
        Assert.Equal("200", await ApiStatusAsync(page));

        // Signing in to Pano again needs no password, but the withdrawn consent is asked for again.
        await page.GotoAsync(Stack.PanoOrigin + "/");
        await page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
        Assert.Equal(0, await page.GetByLabel("Password").CountAsync());
        await session.AllowAsync();
        await page.WaitForURLAsync(Stack.PanoOrigin + "/workspace");

        // 2. Global sign-out at the provider.
        await page.GotoAsync(Stack.IamOrigin + "/manage/sessions");
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign out everywhere" }).ClickAsync();
        await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/account/login", StringComparison.Ordinal));

        // Both applications drop their sessions on the next request, in the original and in the copied profile.
        Assert.Equal("Not signed in to Pano", await BadgeAtAsync(session, Stack.PanoOrigin));
        Assert.Equal("Not signed in to Rapor", await BadgeAtAsync(session, Stack.RaporOrigin));
        Assert.Equal("Not signed in to Rapor", await BadgeAtAsync(copied, Stack.RaporOrigin));
        await copied.Page.GotoAsync(Stack.IamOrigin + "/manage");
        Assert.StartsWith(Stack.IamOrigin + "/account/login", copied.Page.Url);

        // A protected application page leads back to the provider's sign-in form: there is no way to the API.
        await copied.Page.GotoAsync(Stack.RaporOrigin + "/workspace");
        Assert.StartsWith(Stack.IamOrigin + "/account/login", copied.Page.Url);
        var liveGrants = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.CountAsync(x => x.UserId == user.Id && x.RevokedAt == null));
        Assert.Equal(0, liveGrants);
    }

    [Fact]
    public async Task Admin_DisablesAndEnablesAClient_RegistersAMachineClient_AndRotatesItsSecret_InTheBrowser()
    {
        var admin = await MfaFlow.CreateAccountAsync(Stack, Roles.ApplicationAdmin);
        var user = await Stack.CreateUserAsync();
        await using var userSession = await fixture.NewSessionAsync();
        await userSession.SignInToAppAsync(Stack.RaporOrigin, user);
        await userSession.Page.WaitForURLAsync(Stack.RaporOrigin + "/workspace");

        await using var adminSession = await fixture.NewSessionAsync();
        var page = adminSession.Page;
        await page.GotoAsync(Stack.IamOrigin + "/account/login?returnUrl=" + Uri.EscapeDataString($"/admin/clients/{DemoCatalog.RaporClientId}"));
        await adminSession.SignInAtProviderAsync(admin.User);
        await page.WaitForURLAsync(url => url.Contains("/account/mfa", StringComparison.Ordinal));
        await page.GetByLabel("Authentication code").FillAsync(admin.Device.NextCode());
        await page.GetByRole(AriaRole.Button, new() { Name = "Verify" }).ClickAsync();
        await page.WaitForURLAsync($"{Stack.IamOrigin}/admin/clients/{DemoCatalog.RaporClientId}");

        try
        {
            // Disable Rapor: the signed-in user loses the application session and cannot sign in to it again.
            await page.GetByRole(AriaRole.Button, new() { Name = "Disable client" }).ClickAsync();
            await Assertions.Expect(page.GetByRole(AriaRole.Button, new() { Name = "Enable client" })).ToBeVisibleAsync();
            Assert.Equal("Not signed in to Rapor", await BadgeAtAsync(userSession, Stack.RaporOrigin));
            await userSession.Page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
            await userSession.Page.WaitForLoadStateAsync();
            Assert.False(userSession.Page.Url.StartsWith(Stack.RaporOrigin + "/workspace", StringComparison.Ordinal));
            Assert.Equal("Not signed in to Rapor", await BadgeAtAsync(userSession, Stack.RaporOrigin));

            // Enable it again: the central session is still there, so the user is back without a password.
            await page.GetByRole(AriaRole.Button, new() { Name = "Enable client" }).ClickAsync();
            await Assertions.Expect(page.GetByRole(AriaRole.Button, new() { Name = "Disable client" })).ToBeVisibleAsync();
            await userSession.SignInToAppAsync(Stack.RaporOrigin, user: null);
            await userSession.Page.WaitForURLAsync(Stack.RaporOrigin + "/workspace");
        }
        finally
        {
            // Other tests share this stack; Rapor must not stay disabled if an assertion above failed.
            await Stack.InIamAsync(async services =>
            {
                var db = services.GetRequiredService<IamDbContext>();
                var applicationId = await db.Applications.Where(x => x.ClientId == DemoCatalog.RaporClientId).Select(x => x.Id).SingleAsync();
                await db.ClientSettings.Where(x => x.ApplicationId == applicationId).ExecuteUpdateAsync(set => set.SetProperty(x => x.IsDisabled, false));
            });
        }

        // Register a machine client. Its secret is on the page exactly once.
        var clientId = $"e2e-machine-{Guid.NewGuid():N}"[..28];
        await page.GotoAsync(Stack.IamOrigin + "/admin/clients/new");
        await page.Locator("#Form_ClientId").FillAsync(clientId);
        await page.Locator("#Form_Kind").SelectOptionAsync("machine");
        await page.Locator("#Form_DisplayName").FillAsync("E2E machine");
        await page.Locator("input[name='Form.Scopes'][value='workspace.jobs']").CheckAsync();
        await page.GetByRole(AriaRole.Button, new() { Name = "Register client" }).ClickAsync();
        var secret = (await page.GetByTestId("new-secret").InnerTextAsync()).Trim();
        Assert.True(secret.Length >= 32, "a generated secret is expected");
        await page.GotoAsync($"{Stack.IamOrigin}/admin/clients/{clientId}");
        Assert.Equal(0, await page.GetByTestId("new-secret").CountAsync());
        Assert.DoesNotContain(secret, await page.ContentAsync());

        // The machine gets a token for its registered scope only.
        using var machine = new ProtocolClient(Stack, clientId, secret, string.Empty);
        Assert.Equal(HttpStatusCode.OK, (await machine.ClientCredentialsAsync("workspace.jobs")).Status);
        var widened = await machine.ClientCredentialsAsync("workspace.jobs workspace.write");
        Assert.NotEqual(HttpStatusCode.OK, widened.Status);
        Assert.False(widened.Has("access_token"));

        // Rotation without a grace period: the new secret is shown once, the old one stops working at once.
        await page.Locator("#graceMinutes").SelectOptionAsync("0");
        await page.GetByRole(AriaRole.Button, new() { Name = "Rotate secret" }).ClickAsync();
        var rotated = (await page.GetByTestId("new-secret").InnerTextAsync()).Trim();
        Assert.NotEqual(secret, rotated);
        var withOld = await machine.ClientCredentialsAsync("workspace.jobs");
        Assert.Equal(HttpStatusCode.Unauthorized, withOld.Status);
        Assert.Equal("invalid_client", withOld.Error);
        Assert.Equal(HttpStatusCode.OK, (await machine.ClientCredentialsAsync("workspace.jobs", secretOverride: rotated)).Status);
    }

    [Fact]
    public async Task AnotherUsersSession_CannotBeEndedFromTheBrowser_ThroughTheApiOrATamperedForm()
    {
        var victim = await Stack.CreateUserAsync();
        using var victimBrowser = Stack.NewBrowser();
        await Stack.SignInAsync(victimBrowser, victim);
        var victimSession = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions
            .Where(x => x.UserId == victim.Id && x.RevokedAt == null).Select(x => x.Id).SingleAsync());

        var attacker = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        var page = session.Page;
        await page.GotoAsync(Stack.IamOrigin + "/account/login?returnUrl=%2Fmanage%2Fsessions");
        await session.SignInAtProviderAsync(attacker);
        await page.WaitForURLAsync(Stack.IamOrigin + "/manage/sessions");

        // API: with the attacker's own valid anti-forgery token the foreign identifier is simply "not found";
        // without a token the request is refused before it is looked at.
        var statuses = await page.EvaluateAsync<int[]>(
            """
            async (id) => {
              const token = document.querySelector('input[name=__RequestVerificationToken]').value;
              const foreign = await fetch('/api/account/sessions/' + id, { method: 'DELETE', headers: { 'X-CSRF-TOKEN': token } });
              const withoutToken = await fetch('/api/account/sessions/' + id, { method: 'DELETE' });
              const own = await fetch('/api/account/session');
              return [foreign.status, withoutToken.status, own.status];
            }
            """,
            victimSession.ToString());
        Assert.Equal([404, 400, 200], statuses);

        // Page: the hidden identifier of the attacker's own "Sign out" form is replaced by the victim's.
        await page.EvaluateAsync(
            "(id) => { document.querySelector(\"form[action*='handler=Revoke'] input[name=id]\").value = id; }",
            victimSession.ToString());
        await page.Locator("form[action*='handler=Revoke'] button").First.ClickAsync();
        await page.WaitForLoadStateAsync();

        var revokedAt = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions
            .Where(x => x.Id == victimSession).Select(x => x.RevokedAt).SingleAsync());
        Assert.Null(revokedAt);
        Assert.Equal("/manage", (await victimBrowser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
    }
}
