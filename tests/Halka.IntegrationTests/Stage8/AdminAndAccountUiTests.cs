using System.Net;
using Halka.Iam.Admin;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Migrator;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.IntegrationTests.Stage8;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class AdminAndAccountUiTests(StackFixture fixture)
{
    private const string PanoScopes = "openid profile email offline_access workspace.read workspace.write";

    private HalkaStack Stack => fixture.Stack;

    private async Task<(MfaAccount Account, Browser Browser)> SignedInAdminAsync(params string[] roles)
    {
        var account = await MfaFlow.CreateAccountAsync(Stack, roles);
        var browser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, browser, account);
        return (account, browser);
    }

    private static string? Flash(Page page) => page.Find("[role=status]")?.TextContent.Trim() ?? page.Find("[role=alert]")?.TextContent.Trim();

    [Fact]
    public async Task Admin_RoleSeparation_EachRoleOnlyReachesItsOwnPages()
    {
        var (_, security) = await SignedInAdminAsync(Roles.SecurityAdmin);
        var (_, application) = await SignedInAdminAsync(Roles.ApplicationAdmin);
        var (_, platform) = await SignedInAdminAsync(Roles.PlatformAdmin);
        using (security)
        using (application)
        using (platform)
        {
            var securityPages = new[] { "/admin/users", "/admin/sessions", "/admin/grants", "/admin/audit" };
            var applicationPages = new[] { "/admin/clients", "/admin/clients/new", "/admin/scopes", $"/admin/clients/{DemoCatalog.PanoClientId}" };
            var platformPages = new[] { "/admin/keys" };
            var shared = new[] { "/admin", "/admin/ops" };

            async Task ExpectAsync(Browser browser, IEnumerable<string> paths, HttpStatusCode expected)
            {
                foreach (var path in paths)
                {
                    var page = await browser.GetAsync($"{Stack.IamOrigin}{path}");
                    Assert.True(page.Status == expected, $"{path}: expected {(int)expected}, got {(int)page.Status}");
                }
            }

            await ExpectAsync(security, securityPages.Concat(shared), HttpStatusCode.OK);
            await ExpectAsync(security, applicationPages.Concat(platformPages), HttpStatusCode.Forbidden);
            await ExpectAsync(application, applicationPages.Concat(shared), HttpStatusCode.OK);
            await ExpectAsync(application, securityPages.Concat(platformPages), HttpStatusCode.Forbidden);
            await ExpectAsync(platform, securityPages.Concat(applicationPages).Concat(platformPages).Concat(shared), HttpStatusCode.OK);

            // The navigation only offers what the role can open.
            var nav = (await security.GetAsync($"{Stack.IamOrigin}/admin")).Document.QuerySelectorAll("nav[aria-label=Administration] a").Select(link => link.GetAttribute("href")).ToList();
            Assert.Contains("/admin/users", nav);
            Assert.DoesNotContain("/admin/clients", nav);
            Assert.DoesNotContain("/admin/keys", nav);
        }
    }

    [Fact]
    public async Task Admin_UserLifecycle_DisableEnableUnlock_ThroughTheUi_AndSecurityAdminCannotChangeRoles()
    {
        var (admin, browser) = await SignedInAdminAsync(Roles.SecurityAdmin);
        using var _ = browser;
        var target = await Stack.CreateUserAsync();
        using var targetBrowser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(targetBrowser, target, PanoScopes);

        // Search and open the account.
        var list = await browser.GetAsync($"{Stack.IamOrigin}/admin/users?search={Uri.EscapeDataString(target.Email[..18])}");
        Assert.Contains(target.Email, list.Text);
        var detail = await browser.GetAsync($"{Stack.IamOrigin}/admin/users/{target.Id}");
        Assert.Single(detail.Document.QuerySelectorAll("form[action*='handler=RevokeSession']"));
        Assert.Single(detail.Document.QuerySelectorAll("form[action*='handler=RevokeGrant']"));
        Assert.Empty(detail.Document.QuerySelectorAll("form[action*='handler=Role']"));

        // Disable: the user's session, tokens and API access end at once.
        var disabled = await browser.SubmitAsync(detail, "form[action*='handler=Disable']");
        Assert.Contains("was disabled", Flash(disabled));
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        Assert.Equal("/account/login", (await targetBrowser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        var enabled = await browser.SubmitAsync(disabled, "form[action*='handler=Enable']");
        Assert.Contains("was enabled", Flash(enabled));

        // Lock the account out with wrong passwords, then clear the lockout.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            await Stack.SignInAsync(targetBrowser, target with { Password = "wrong-password-value" });
        }

        Assert.Equal("/account/login", (await Stack.SignInAsync(targetBrowser, target)).Url.AbsolutePath);
        var locked = await browser.GetAsync($"{Stack.IamOrigin}/admin/users/{target.Id}");
        Assert.Contains("Locked out", locked.Text);
        var unlocked = await browser.SubmitAsync(locked, "form[action*='handler=Unlock']");
        Assert.Contains("lockout was cleared", Flash(unlocked));
        Assert.Equal("/manage", (await Stack.SignInAsync(targetBrowser, target)).Url.AbsolutePath);

        // A SecurityAdmin posting the role handler directly is refused; nothing changes.
        var token = unlocked.Find("input[name=__RequestVerificationToken]")!.GetAttribute("value")!;
        var forged = await browser.PostFormAsync($"{Stack.IamOrigin}/admin/users/{target.Id}?handler=Role",
            [new("role", Roles.PlatformAdmin), new("grant", "true"), new("__RequestVerificationToken", token)]);
        Assert.Equal(HttpStatusCode.Forbidden, forged.Status);
        var self = await browser.PostFormAsync($"{Stack.IamOrigin}/admin/users/{admin.User.Id}?handler=Role",
            [new("role", Roles.PlatformAdmin), new("grant", "true"), new("__RequestVerificationToken", token)]);
        Assert.Equal(HttpStatusCode.Forbidden, self.Status);
        var roles = await Stack.InIamAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            return (await users.GetRolesAsync((await users.FindByIdAsync(target.Id.ToString()))!))
                .Concat(await users.GetRolesAsync((await users.FindByIdAsync(admin.User.Id.ToString()))!)).ToList();
        });
        Assert.DoesNotContain(Roles.PlatformAdmin, roles);
    }

    [Fact]
    public async Task Admin_SessionAndGrantRevocation_IsBoundToTheAccountInTheRoute()
    {
        var (_, browser) = await SignedInAdminAsync(Roles.SecurityAdmin);
        using var _b = browser;
        var first = await Stack.CreateUserAsync();
        var second = await Stack.CreateUserAsync();
        using var firstBrowser = Stack.NewBrowser();
        using var secondBrowser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var firstTokens = await pano.SignInAsync(firstBrowser, first, PanoScopes);
        var secondTokens = await pano.SignInAsync(secondBrowser, second, PanoScopes);
        var secondSession = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.Where(x => x.UserId == second.Id).Select(x => x.Id).SingleAsync());
        var secondGrant = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.Where(x => x.UserId == second.Id).Select(x => x.AuthorizationId).SingleAsync());

        // Identifiers of another account submitted through the first account's page are not acted on.
        var detail = await browser.GetAsync($"{Stack.IamOrigin}/admin/users/{first.Id}");
        var crossSession = await browser.SubmitAsync(detail, "form[action*='handler=RevokeSession']", new Dictionary<string, string> { ["sessionId"] = secondSession.ToString() });
        var crossGrant = await browser.SubmitAsync(detail, "form[action*='handler=RevokeGrant']", new Dictionary<string, string> { ["authorizationId"] = secondGrant.ToString() });
        Assert.Equal(HttpStatusCode.NotFound, crossSession.Status);
        Assert.Equal(HttpStatusCode.NotFound, crossGrant.Status);
        Assert.Equal(HttpStatusCode.OK, (await pano.ApiAsync(HttpMethod.Get, "/notes", secondTokens.AccessToken)).Status);
        Assert.Equal("/manage", (await secondBrowser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // The legitimate revocations work and take effect immediately.
        var grantRevoked = await browser.SubmitAsync(detail, "form[action*='handler=RevokeGrant']");
        Assert.Contains("grant was revoked", Flash(grantRevoked));
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", firstTokens.AccessToken)).Status);
        var sessionEnded = await browser.SubmitAsync(grantRevoked, "form[action*='handler=RevokeSession']");
        Assert.Contains("session was ended", Flash(sessionEnded));
        Assert.Equal("/account/login", (await firstBrowser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // The global lists act on any account and show the remaining rows.
        var sessions = await browser.GetAsync($"{Stack.IamOrigin}/admin/sessions");
        Assert.Contains(second.Email, sessions.Text);
        var grants = await browser.GetAsync($"{Stack.IamOrigin}/admin/grants");
        var row = grants.Document.QuerySelectorAll("table.data tbody tr").Single(item => item.TextContent.Contains(second.Email, StringComparison.Ordinal));
        var revoked = await browser.PostFormAsync($"{Stack.IamOrigin}/admin/grants?handler=Revoke",
        [
            new("id", row.QuerySelector("input[name=id]")!.GetAttribute("value")!),
            new("__RequestVerificationToken", row.QuerySelector("input[name=__RequestVerificationToken]")!.GetAttribute("value")!),
        ]);
        Assert.Equal("/admin/grants", revoked.Url.AbsolutePath);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", secondTokens.AccessToken)).Status);

        // Everything above is in the audit log, viewable but without e-mail addresses.
        var audit = await browser.GetAsync($"{Stack.IamOrigin}/admin/audit?subject={first.Id}");
        Assert.Contains("session.ended", audit.Text);
        Assert.DoesNotContain(first.Email, audit.Document.QuerySelector("table.data")!.TextContent);
    }

    [Fact]
    public async Task Admin_ClientRegistration_ShowsTheSecretOnce_AndRotationWorksThroughTheUi()
    {
        var (_, browser) = await SignedInAdminAsync(Roles.ApplicationAdmin);
        using var _b = browser;
        var clientId = $"ui-machine-{Guid.NewGuid():N}"[..26];

        // Invalid input is explained and nothing is created.
        var form = await browser.GetAsync($"{Stack.IamOrigin}/admin/clients/new");
        var invalid = await browser.SubmitAsync(form, "form[action='/admin/clients/new']", new Dictionary<string, string>
        {
            ["Form.ClientId"] = "Not Valid",
            ["Form.DisplayName"] = "Broken",
            ["Form.Kind"] = "web",
            ["Form.RedirectUris"] = "http://insecure.example/cb\nhttps://ok.example/*",
        });
        Assert.NotNull(invalid.Find("[role=alert]"));
        Assert.Null(invalid.Find("[data-testid=new-secret]"));

        // A machine client with one scope.
        var created = await browser.SubmitAsync(form, "form[action='/admin/clients/new']", new Dictionary<string, string>
        {
            ["Form.ClientId"] = clientId,
            ["Form.DisplayName"] = "UI machine",
            ["Form.Kind"] = "machine",
            ["Form.Scopes"] = DemoCatalog.WorkspaceRead,
        });
        var secret = created.Find("[data-testid=new-secret]")!.TextContent.Trim();
        Assert.Equal(43, secret.Length);
        Assert.Contains("no-store", created.Header("Cache-Control"));

        // The secret works, and no later page shows it again.
        using var machine = new ProtocolClient(Stack, clientId, secret, string.Empty);
        Assert.Equal(HttpStatusCode.OK, (await machine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead)).Status);
        var detail = await browser.GetAsync($"{Stack.IamOrigin}/admin/clients/{clientId}");
        var list = await browser.GetAsync($"{Stack.IamOrigin}/admin/clients");
        Assert.DoesNotContain(secret, detail.Body);
        Assert.DoesNotContain(secret, list.Body);
        Assert.Contains(clientId, list.Text);
        var storedHash = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Applications.Where(x => x.ClientId == clientId).Select(x => x.ClientSecret).SingleAsync());
        Assert.DoesNotContain(storedHash!, detail.Body);

        // Rotate without grace: a new secret is shown once, the old one stops working.
        var rotated = await browser.SubmitAsync(detail, "form[action*='handler=Rotate']", new Dictionary<string, string> { ["graceMinutes"] = "0" });
        var newSecret = rotated.Find("[data-testid=new-secret]")!.TextContent.Trim();
        Assert.NotEqual(secret, newSecret);
        using var rotatedMachine = new ProtocolClient(Stack, clientId, newSecret, string.Empty);
        Assert.Equal(HttpStatusCode.OK, (await rotatedMachine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead)).Status);
        Assert.DoesNotContain(newSecret, (await browser.GetAsync($"{Stack.IamOrigin}/admin/clients/{clientId}")).Body);

        // Disable through the UI.
        var disabled = await browser.SubmitAsync(await browser.GetAsync($"{Stack.IamOrigin}/admin/clients/{clientId}"), "form[action*='handler=Disable']");
        Assert.Contains("was disabled", Flash(disabled));
        Assert.Equal(HttpStatusCode.Unauthorized, (await rotatedMachine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead)).Status);

        // The posted form cannot change identifier or kind of an existing registration.
        var tampered = await browser.SubmitAsync(disabled, "form[action*='handler=Save']", new Dictionary<string, string>
        {
            ["Form.ClientId"] = DemoCatalog.PanoClientId,
            ["Form.Kind"] = "web",
            ["Form.DisplayName"] = "Renamed machine",
            ["Form.Scopes"] = DemoCatalog.WorkspaceRead,
        });
        Assert.Equal($"/admin/clients/{clientId}", tampered.Url.AbsolutePath);
        var kinds = await Stack.InIamAsync(services => (
            from application in services.GetRequiredService<IamDbContext>().Applications
            join settings in services.GetRequiredService<IamDbContext>().ClientSettings on application.Id equals settings.ApplicationId
            where application.ClientId == clientId || application.ClientId == DemoCatalog.PanoClientId
            select new { application.ClientId, application.DisplayName, settings.Kind }).ToListAsync());
        Assert.Contains(kinds, row => row.ClientId == clientId && row.Kind == ClientKind.Machine && row.DisplayName == "Renamed machine");
        Assert.Contains(kinds, row => row.ClientId == DemoCatalog.PanoClientId && row.DisplayName == "Pano");
    }

    [Fact]
    public async Task Admin_ScopeCreation_AndKeyPage_NeedTheRightRole_AndWorkThroughTheUi()
    {
        var (_, application) = await SignedInAdminAsync(Roles.ApplicationAdmin);
        var (_, platform) = await SignedInAdminAsync(Roles.PlatformAdmin);
        using var _a = application;
        using var _p = platform;

        var scopeName = $"workspace.t{Guid.NewGuid():N}"[..24];
        var scopes = await application.GetAsync($"{Stack.IamOrigin}/admin/scopes");
        var added = await application.SubmitAsync(scopes, "form[action='/admin/scopes']", new Dictionary<string, string>
        {
            ["Name"] = scopeName,
            ["DisplayName"] = "Temporary scope",
            ["Description"] = "Created by a test",
            ["Resource"] = DemoCatalog.WorkspaceApiClientId,
        });
        Assert.Contains(scopeName, added.Find("table.data")!.TextContent);
        var reserved = await application.SubmitAsync(added, "form[action='/admin/scopes']", new Dictionary<string, string> { ["Name"] = "openid", ["DisplayName"] = "x" });
        Assert.NotNull(reserved.Find("[role=alert]"));

        // Keys: only identifiers are shown; retiring a key that still protects tokens is not offered.
        var keys = await platform.GetAsync($"{Stack.IamOrigin}/admin/keys");
        Assert.Equal(HttpStatusCode.OK, keys.Status);
        Assert.DoesNotContain("PRIVATE KEY", keys.Body);
        var stored = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ProtocolKeys.AsNoTracking().ToListAsync());
        Assert.All(stored, key => Assert.DoesNotContain(Convert.ToBase64String(key.ProtectedPrivateKey), keys.Body));

        // An emergency revocation without the typed confirmation does nothing.
        var active = stored.First(key => key.Use == ProtocolKeyUse.Signing && key.Status == ProtocolKeyStatus.Active);
        var unconfirmed = await platform.SubmitAsync(keys, "form[action*='handler=Emergency']", new Dictionary<string, string>
        {
            ["id"] = active.Id.ToString(),
            ["reason"] = "test",
            ["confirmation"] = "revoke",
        });
        Assert.Contains("Type REVOKE", Flash(unconfirmed));
        Assert.Equal(ProtocolKeyStatus.Active, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ProtocolKeys.Where(x => x.Id == active.Id).Select(x => x.Status).SingleAsync()));
    }

    [Fact]
    public async Task Account_ChangePassword_KeepsThisSession_EndsOthers_AndTheOldPasswordStopsWorking()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var other = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        await Stack.SignInAsync(browser, user);
        var otherTokens = await pano.SignInAsync(other, user, PanoScopes);
        var newPassword = $"Pw-{Guid.NewGuid():N}";

        var form = await browser.GetAsync($"{Stack.IamOrigin}/manage/password");
        var wrong = await browser.SubmitAsync(form, "form[action='/manage/password']", new Dictionary<string, string> { ["CurrentPassword"] = "not-my-password", ["NewPassword"] = newPassword });
        Assert.Contains("current password is not correct", wrong.Find("[role=alert]")!.TextContent);
        var weak = await browser.SubmitAsync(form, "form[action='/manage/password']", new Dictionary<string, string> { ["CurrentPassword"] = user.Password, ["NewPassword"] = "short" });
        Assert.NotNull(weak.Find("[role=alert]"));

        var changed = await browser.SubmitAsync(form, "form[action='/manage/password']", new Dictionary<string, string> { ["CurrentPassword"] = user.Password, ["NewPassword"] = newPassword });
        Assert.Contains("password was changed", Flash(changed));

        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.Equal("/account/login", (await other.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", otherTokens.AccessToken)).Status);
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(otherTokens.RefreshToken)).Error);
        using var fresh = Stack.NewBrowser();
        Assert.Equal("/account/login", (await Stack.SignInAsync(fresh, user)).Url.AbsolutePath);
        Assert.Equal("/manage", (await Stack.SignInAsync(fresh, user with { Password = newPassword })).Url.AbsolutePath);
    }

    [Fact]
    public async Task Account_ConnectedApps_AndActivity_ShowOnlyOwnData_AndWithdrawingAccessKillsTokens()
    {
        var user = await Stack.CreateUserAsync();
        var stranger = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var strangerBrowser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        var panoTokens = await pano.SignInAsync(browser, user, PanoScopes);
        var raporTokens = await rapor.SignInAsync(browser, user, "openid profile offline_access workspace.read");
        await Stack.SignInAsync(strangerBrowser, stranger);

        var apps = await browser.GetAsync($"{Stack.IamOrigin}/manage/apps");
        Assert.Equal(2, apps.Document.QuerySelectorAll("table.data tbody tr").Length);
        Assert.Empty((await strangerBrowser.GetAsync($"{Stack.IamOrigin}/manage/apps")).Document.QuerySelectorAll("table.data tbody tr"));

        // A user who never allowed Pano cannot "revoke" anything by naming it: there is nothing of theirs to act on.
        var strangerApps = await strangerBrowser.GetAsync($"{Stack.IamOrigin}/manage/apps");
        var token = strangerApps.Find("input[name=__RequestVerificationToken]")!.GetAttribute("value")!;
        var foreign = await strangerBrowser.PostFormAsync($"{Stack.IamOrigin}/manage/apps?handler=Revoke", [new("clientId", DemoCatalog.PanoClientId), new("__RequestVerificationToken", token)]);
        Assert.Equal(HttpStatusCode.NotFound, foreign.Status);
        Assert.Equal(HttpStatusCode.OK, (await pano.ApiAsync(HttpMethod.Get, "/notes", panoTokens.AccessToken)).Status);

        var panoRow = apps.Document.QuerySelectorAll("table.data tbody tr").Single(row => row.TextContent.Contains("pano-web", StringComparison.Ordinal));
        var withdrawn = await browser.PostFormAsync($"{Stack.IamOrigin}/manage/apps?handler=Revoke",
        [
            new("clientId", panoRow.QuerySelector("input[name=clientId]")!.GetAttribute("value")!),
            new("__RequestVerificationToken", panoRow.QuerySelector("input[name=__RequestVerificationToken]")!.GetAttribute("value")!),
        ]);
        Assert.Contains("Access was withdrawn", Flash(withdrawn));
        Assert.Single(withdrawn.Document.QuerySelectorAll("table.data tbody tr"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", panoTokens.AccessToken)).Status);
        Assert.Equal(HttpStatusCode.OK, (await rapor.ApiAsync(HttpMethod.Get, "/notes", raporTokens.AccessToken)).Status);

        var activity = await browser.GetAsync($"{Stack.IamOrigin}/manage/activity");
        Assert.Contains("consent.revoked", activity.Text);
        Assert.Contains("session.started", activity.Text);
        var strangerActivity = await strangerBrowser.GetAsync($"{Stack.IamOrigin}/manage/activity");
        Assert.DoesNotContain("consent.revoked", strangerActivity.Text);
        Assert.DoesNotContain(user.Id.ToString(), strangerActivity.Body);
    }
}

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class LastAdminTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private Task<List<Guid>> ActivePlatformAdminsAsync()
        => Stack.InIamAsync(services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            return (
                from userRole in db.UserRoles
                join role in db.Roles on userRole.RoleId equals role.Id
                join user in db.Users on userRole.UserId equals user.Id
                where role.Name == Roles.PlatformAdmin && !user.IsDisabled
                select user.Id).ToListAsync();
        });

    /// <summary>
    /// The stack is shared, so other tests may have created PlatformAdmins. This test first reduces the set to two
    /// accounts it controls (through the same guarded service), then races the removal of both.
    /// </summary>
    [Fact]
    public async Task LastAdmin_ConcurrentDemotionAndDisable_AlwaysLeavesOneActivePlatformAdmin()
    {
        var first = await Stack.CreateUserAsync(Roles.PlatformAdmin);
        var second = await Stack.CreateUserAsync(Roles.PlatformAdmin);
        foreach (var other in (await ActivePlatformAdminsAsync()).Where(id => id != first.Id && id != second.Id))
        {
            var removed = await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetRoleAsync(other, Roles.PlatformAdmin, false, first.Id, CancellationToken.None));
            Assert.True(removed.Succeeded);
        }

        Assert.Equal(2, (await ActivePlatformAdminsAsync()).Count);

        // Each removes the other, at the same moment, many times over (roles are restored between rounds).
        for (var round = 0; round < 6; round++)
        {
            using var barrier = new Barrier(2);
            Task<AdminResult> Race(Guid target, Guid actor, bool disable) => Task.Run(async () =>
            {
                barrier.SignalAndWait(TimeSpan.FromSeconds(10));
                return await Stack.InIamAsync(services => disable
                    ? services.GetRequiredService<UserAdminService>().SetDisabledAsync(target, true, actor, CancellationToken.None)
                    : services.GetRequiredService<UserAdminService>().SetRoleAsync(target, Roles.PlatformAdmin, false, actor, CancellationToken.None));
            });

            var results = await Task.WhenAll(Race(second.Id, first.Id, round % 2 == 0), Race(first.Id, second.Id, round % 3 == 0));

            Assert.Equal(1, results.Count(result => result.Succeeded));
            Assert.Contains("last active PlatformAdmin", results.Single(result => !result.Succeeded).Error);
            var remaining = await ActivePlatformAdminsAsync();
            Assert.Single(remaining);

            // Restore both for the next round (with the surviving administrator as actor).
            foreach (var id in new[] { first.Id, second.Id })
            {
                Assert.True((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetDisabledAsync(id, false, remaining[0], CancellationToken.None))).Succeeded);
                Assert.True((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetRoleAsync(id, Roles.PlatformAdmin, true, remaining[0], CancellationToken.None))).Succeeded);
            }
        }

        // Sequentially: the last one cannot be demoted or disabled, and nobody can disable themselves.
        Assert.True((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetRoleAsync(second.Id, Roles.PlatformAdmin, false, first.Id, CancellationToken.None))).Succeeded);
        Assert.False((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetRoleAsync(first.Id, Roles.PlatformAdmin, false, first.Id, CancellationToken.None))).Succeeded);
        Assert.False((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetDisabledAsync(first.Id, true, second.Id, CancellationToken.None))).Succeeded);
        Assert.False((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetDisabledAsync(first.Id, true, first.Id, CancellationToken.None))).Succeeded);
        Assert.Equal([first.Id], await ActivePlatformAdminsAsync());
        Assert.False((await Stack.InIamAsync(services => services.GetRequiredService<UserAdminService>().SetRoleAsync(second.Id, Roles.User, false, first.Id, CancellationToken.None))).Succeeded);
    }

    [Fact]
    public async Task Admin_RoleChange_ThroughTheUi_NeedsPlatformAdmin_AndDemotionAppliesOnTheNextRequest()
    {
        var platform = await MfaFlow.CreateAccountAsync(Stack, Roles.PlatformAdmin);
        var colleague = await MfaFlow.CreateAccountAsync(Stack);
        using var platformBrowser = Stack.NewBrowser();
        using var colleagueBrowser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, platformBrowser, platform);
        await MfaFlow.SignInAsync(Stack, colleagueBrowser, colleague);
        Assert.Equal(HttpStatusCode.Forbidden, (await colleagueBrowser.GetAsync($"{Stack.IamOrigin}/admin/users")).Status);

        // Grant SecurityAdmin: effective for the colleague's existing session without signing in again.
        var detail = await platformBrowser.GetAsync($"{Stack.IamOrigin}/admin/users/{colleague.User.Id}");
        var grantForm = detail.Document.QuerySelectorAll("form[action*='handler=Role']").Single(form => form.QuerySelector("input[name=role]")!.GetAttribute("value") == Roles.SecurityAdmin);
        async Task<Page> SubmitRoleAsync(AngleSharp.Dom.IElement form) => await platformBrowser.PostFormAsync($"{Stack.IamOrigin}/admin/users/{colleague.User.Id}?handler=Role",
            form.QuerySelectorAll("input").Select(input => new KeyValuePair<string, string>(input.GetAttribute("name")!, input.GetAttribute("value") ?? string.Empty)));
        var granted = await SubmitRoleAsync(grantForm);
        Assert.Contains("was granted", granted.Find("[role=status]")!.TextContent);
        Assert.Equal(HttpStatusCode.OK, (await colleagueBrowser.GetAsync($"{Stack.IamOrigin}/admin/users")).Status);

        // Remove it again: the colleague's very next request is refused, with the same cookie.
        var removeForm = granted.Document.QuerySelectorAll("form[action*='handler=Role']").Single(form => form.QuerySelector("input[name=role]")!.GetAttribute("value") == Roles.SecurityAdmin);
        Assert.Equal("false", removeForm.QuerySelector("input[name=grant]")!.GetAttribute("value"));
        var removed = await SubmitRoleAsync(removeForm);
        Assert.Contains("was removed", removed.Find("[role=status]")!.TextContent);
        Assert.Equal(HttpStatusCode.Forbidden, (await colleagueBrowser.GetAsync($"{Stack.IamOrigin}/admin/users")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await colleagueBrowser.GetAsync($"{Stack.IamOrigin}/admin")).Status);
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class AdminStepUpTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Admin_SensitiveActions_NeedARecentStepUp_AStolenAdminCookieAloneChangesNothing()
    {
        var admin = await MfaFlow.CreateAccountAsync(Stack, Roles.PlatformAdmin);
        var target = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, browser, admin);
        var detail = await browser.GetAsync($"{Stack.IamOrigin}/admin/users/{target.Id}");
        var keys = await browser.GetAsync($"{Stack.IamOrigin}/admin/keys");
        var client = await browser.GetAsync($"{Stack.IamOrigin}/admin/clients/{DemoCatalog.RaporClientId}");
        var keyCountBefore = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ProtocolKeys.CountAsync());

        // Six minutes later an attacker with a copy of the admin's cookie can still read, but every mutation
        // is redirected to the step-up page, which wants the authenticator.
        Stack.Time.Advance(TimeSpan.FromMinutes(6));
        using var stolen = browser.CloneWithCookies();
        Assert.Equal(HttpStatusCode.OK, (await stolen.GetAsync($"{Stack.IamOrigin}/admin/users/{target.Id}")).Status);

        var disable = await stolen.SubmitAsync(detail, "form[action*='handler=Disable']");
        var role = await stolen.SubmitAsync(detail, "form[action*='handler=Role']");
        var rotateKey = await stolen.SubmitAsync(keys, "form[action*='handler=Rotate']");
        var rotateSecret = await stolen.SubmitAsync(client, "form[action*='handler=Rotate']", new Dictionary<string, string> { ["graceMinutes"] = "0" });
        var disableClient = await stolen.SubmitAsync(client, "form[action*='handler=Disable']");
        foreach (var page in new[] { disable, role, rotateKey, rotateSecret, disableClient })
        {
            Assert.Equal("/account/step-up", page.Url.AbsolutePath);
            Assert.Null(page.Find("input[type=password]"));
            Assert.Null(page.Find("[data-testid=new-secret]"));
        }

        Assert.False(await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == target.Id).Select(x => x.IsDisabled).SingleAsync()));
        Assert.Equal(keyCountBefore, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ProtocolKeys.CountAsync()));
        var raporDisabled = await Stack.InIamAsync(services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            return (
                from application in db.Applications
                join settings in db.ClientSettings on application.Id equals settings.ApplicationId
                where application.ClientId == DemoCatalog.RaporClientId
                select settings.IsDisabled).SingleAsync();
        });
        Assert.False(raporDisabled);

        // The Rapor secret was not rotated either: the original still authenticates.
        using var rapor = ProtocolClient.Rapor(Stack);
        Assert.Equal(HttpStatusCode.OK, (await rapor.IntrospectAsync("not-a-token")).Status);

        // The real administrator confirms with a code and is returned to the page to repeat the action.
        var confirmed = await browser.SubmitAsync(disable, "form[action*='handler=Totp']", new Dictionary<string, string> { ["code"] = admin.Device.NextCode() });
        Assert.Equal($"/admin/users/{target.Id}", confirmed.Url.AbsolutePath);
        var done = await browser.SubmitAsync(confirmed, "form[action*='handler=Disable']");
        Assert.Contains("was disabled", done.Find("[role=status]")!.TextContent);
        Assert.True(await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == target.Id).Select(x => x.IsDisabled).SingleAsync()));
    }
}
