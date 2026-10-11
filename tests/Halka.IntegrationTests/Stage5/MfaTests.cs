using System.Net;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mfa;
using Halka.Iam.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Halka.IntegrationTests.Stage5;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class MfaTests(StackFixture fixture)
{
    private const string PanoScopes = "openid profile email offline_access workspace.read workspace.write";

    private HalkaStack Stack => fixture.Stack;

    private bool HasSession(Browser browser) => browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName) is not null;

    private Task<UserSession> ActiveSessionAsync(Guid userId)
        => Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.AsNoTracking().SingleAsync(x => x.UserId == userId && x.RevokedAt == null));

    [Fact]
    public async Task Enrollment_IsOnlyActivatedByAValidCode_AndTheSecretIsProtectedAtRest()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, user);

        var page = await browser.GetAsync($"{Stack.IamOrigin}/manage/mfa/enroll");
        var secret = page.Find("[data-testid=totp-secret]")!.TextContent.Trim();
        Assert.Contains("no-store", page.Header("Cache-Control"));
        Assert.StartsWith("data:image/png;base64,", page.Find("img.qr")!.GetAttribute("src"));
        Assert.DoesNotContain(page.Document.QuerySelectorAll("img, script, link"), element =>
            (element.GetAttribute("src") ?? element.GetAttribute("href") ?? string.Empty).StartsWith("http", StringComparison.OrdinalIgnoreCase));

        // A wrong code does not activate anything: the next sign-in still has no second step.
        var wrong = await browser.SubmitAsync(page, "form[action='/manage/mfa/enroll']", new Dictionary<string, string> { ["code"] = "000000" });
        Assert.NotNull(wrong.Find("[role=alert]"));
        Assert.Equal(secret, wrong.Find("[data-testid=totp-secret]")!.TextContent.Trim());
        Assert.False(await Stack.InIamAsync(services => services.GetRequiredService<MfaService>().IsEnabledAsync(user.Id, CancellationToken.None)));
        using var other = Stack.NewBrowser();
        Assert.Equal("/manage", (await Stack.SignInAsync(other, user)).Url.AbsolutePath);

        // The database holds neither the Base32 key nor its raw bytes.
        var stored = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserMfa.AsNoTracking().SingleAsync(x => x.UserId == user.Id));
        Assert.Equal(MfaStatus.Pending, stored.Status);
        var raw = OtpNet.Base32Encoding.ToBytes(secret);
        Assert.False(stored.ProtectedSecret.AsSpan().IndexOf(raw) >= 0);
        Assert.DoesNotContain(secret, System.Text.Encoding.ASCII.GetString(stored.ProtectedSecret));

        // A valid code activates it, shows the recovery codes once, and ends the other session.
        var device = new TotpDevice(Stack, raw);
        var done = await browser.SubmitAsync(wrong, "form[action='/manage/mfa/enroll']", new Dictionary<string, string> { ["code"] = device.NextCode() });
        var codes = done.Document.QuerySelectorAll("[data-testid=recovery-codes] li").Select(item => item.TextContent.Trim()).ToList();
        Assert.Equal(10, codes.Count);
        Assert.Equal(10, codes.Distinct().Count());
        Assert.All(codes, code => Assert.Matches("^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$", code));
        Assert.Equal("/account/login", (await other.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // Neither the key nor the codes can be displayed again.
        var again = await browser.GetAsync($"{Stack.IamOrigin}/manage/mfa/enroll");
        Assert.Equal("/manage/mfa", again.Url.AbsolutePath);
        Assert.DoesNotContain(secret, again.Body);
        Assert.All(codes, code => Assert.DoesNotContain(code, again.Body));
        var hashes = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().RecoveryCodes.AsNoTracking().Where(x => x.UserId == user.Id).ToListAsync());
        Assert.Equal(10, hashes.Count);
        Assert.All(hashes, row => Assert.Equal(32, row.CodeHash.Length));

        // The session that enrolled is now a multi-factor session.
        var session = await ActiveSessionAsync(user.Id);
        Assert.Equal("pwd otp mfa", session.Amr);
        Assert.NotNull(session.MfaVerifiedAt);
    }

    [Fact]
    public async Task Login_WithMfa_PasswordAloneGivesNoSession_UntilAValidCode()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);

        var codePage = await MfaFlow.PasswordStepAsync(Stack, browser, account.User, "/manage/sessions");
        Assert.Equal("/account/mfa", codePage.Url.AbsolutePath);
        Assert.False(HasSession(browser));
        Assert.NotNull(browser.Cookie(Stack.IamOrigin, PendingChallengeCookie.CookieName));

        // The pending-challenge cookie is not an authenticated session anywhere.
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync($"{Stack.IamOrigin}/api/account/session")).Status);
        var silent = await client.AuthorizeAsync(browser, client.AuthorizeUrl(PanoScopes, Pkce.Create(), overrides: new Dictionary<string, string?> { ["prompt"] = "none" }));
        Assert.Equal("login_required", silent.Error);

        // A wrong code keeps the user on the page without a session.
        var wrong = await MfaFlow.SubmitCodeAsync(browser, codePage, "123456");
        Assert.Equal("/account/mfa", wrong.Url.AbsolutePath);
        Assert.NotNull(wrong.Find("[role=alert]"));
        Assert.False(HasSession(browser));

        var landing = await MfaFlow.SubmitCodeAsync(browser, wrong, account.Device.NextCode());
        Assert.Equal("/manage/sessions", landing.Url.AbsolutePath);
        Assert.True(HasSession(browser));
        Assert.Null(browser.Cookie(Stack.IamOrigin, PendingChallengeCookie.CookieName));
        Assert.Equal("pwd otp mfa", (await ActiveSessionAsync(account.User.Id)).Amr);

        // Tokens report exactly what happened, and the API's sensitive endpoint accepts this session.
        var tokens = await client.SignInAsync(browser, account.User, PanoScopes);
        var amr = new JsonWebToken(tokens.IdToken).Claims.Where(claim => claim.Type == "amr").Select(claim => claim.Value).ToList();
        Assert.Equal(["pwd", "otp", "mfa"], amr);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes/sensitive", tokens.AccessToken)).Status);
    }

    [Fact]
    public async Task Totp_ClockSkewOfOneStepIsAccepted_TwoStepsIsNot()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        var device = account.Device;
        var current = device.CurrentStep;
        Assert.True(device.LastStep < current, "the enrollment used the previous step, so the current and next steps are still unused");

        using var late = Stack.NewBrowser();
        var latePage = await MfaFlow.PasswordStepAsync(Stack, late, account.User);
        // Two steps ahead of the server clock: outside the window.
        var tooEarly = await MfaFlow.SubmitCodeAsync(late, latePage, device.CodeForStep(current + 2));
        Assert.Equal("/account/mfa", tooEarly.Url.AbsolutePath);
        Assert.False(HasSession(late));
        // Two steps behind: outside the window as well.
        var tooOld = await MfaFlow.SubmitCodeAsync(late, tooEarly, device.CodeForStep(current - 2));
        Assert.Equal("/account/mfa", tooOld.Url.AbsolutePath);
        Assert.False(HasSession(late));

        // One step ahead (device clock slightly fast): accepted.
        var ok = await MfaFlow.SubmitCodeAsync(late, tooOld, device.CodeForStep(current + 1));
        Assert.Equal("/manage", ok.Url.AbsolutePath);
        Assert.True(HasSession(late));
    }

    [Fact]
    public async Task Totp_SameCode_CannotBeUsedTwice_AndOlderStepsAreRefusedAfterANewerOne()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        var device = account.Device;
        var current = device.CurrentStep;

        using var first = Stack.NewBrowser();
        var firstPage = await MfaFlow.PasswordStepAsync(Stack, first, account.User);
        Assert.Equal("/manage", (await MfaFlow.SubmitCodeAsync(first, firstPage, device.CodeForStep(current))).Url.AbsolutePath);

        // The very same code inside its own validity period is a replay.
        using var replay = Stack.NewBrowser();
        var replayPage = await MfaFlow.PasswordStepAsync(Stack, replay, account.User);
        var replayed = await MfaFlow.SubmitCodeAsync(replay, replayPage, device.CodeForStep(current));
        Assert.Equal("/account/mfa", replayed.Url.AbsolutePath);
        Assert.False(HasSession(replay));

        // A code of the next step is still fine afterwards.
        Assert.Equal("/manage", (await MfaFlow.SubmitCodeAsync(replay, replayed, device.CodeForStep(current + 1))).Url.AbsolutePath);
    }

    [Fact]
    public async Task Totp_ParallelSameCode_IsAcceptedExactlyOnce()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        var code = account.Device.NextCode();

        // Service level: eight verifications of the same code, released together.
        using var start = new ManualResetEventSlim(false);
        var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            start.Wait();
            return await Stack.InIamAsync(services => services.GetRequiredService<MfaService>().VerifyTotpAsync(account.User.Id, code, CancellationToken.None));
        })).ToList();
        start.Set();
        var results = await Task.WhenAll(attempts);
        Assert.Equal(1, results.Count(accepted => accepted));

        // HTTP level: two browsers at the code page submit the same fresh code at the same time.
        var second = account.Device.NextCode();
        using var a = Stack.NewBrowser();
        using var b = Stack.NewBrowser();
        var pageA = await MfaFlow.PasswordStepAsync(Stack, a, account.User);
        var pageB = await MfaFlow.PasswordStepAsync(Stack, b, account.User);
        var pages = await Task.WhenAll(MfaFlow.SubmitCodeAsync(a, pageA, second), MfaFlow.SubmitCodeAsync(b, pageB, second));
        Assert.Equal(1, pages.Count(page => page.Url.AbsolutePath == "/manage"));
        Assert.Equal(1, new[] { a, b }.Count(HasSession));
        Assert.Equal(1, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.CountAsync(x => x.UserId == account.User.Id && x.RevokedAt == null)));
    }

    [Fact]
    public async Task Challenge_AttemptLimit_ForcesTheUserBackToThePassword()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        var page = await MfaFlow.PasswordStepAsync(Stack, browser, account.User);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            page = await MfaFlow.SubmitCodeAsync(browser, page, "111111");
            Assert.Equal("/account/mfa", page.Url.AbsolutePath);
        }

        // The challenge is exhausted: even the correct code is no longer accepted for it.
        var exhausted = await MfaFlow.SubmitCodeAsync(browser, page, account.Device.NextCode());
        Assert.Equal("/account/login", exhausted.Url.AbsolutePath);
        Assert.Contains("expired or had too many attempts", exhausted.Text);
        Assert.False(HasSession(browser));
        Assert.Null(browser.Cookie(Stack.IamOrigin, PendingChallengeCookie.CookieName));
    }

    [Fact]
    public async Task Recovery_CodeSignsInOnce_ParallelUseSucceedsOnce_AndIsReportedWithoutOtp()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        var code = account.RecoveryCodes[0];

        using var a = Stack.NewBrowser();
        using var b = Stack.NewBrowser();
        var pageA = await MfaFlow.PasswordStepAsync(Stack, a, account.User);
        var pageB = await MfaFlow.PasswordStepAsync(Stack, b, account.User);
        var pages = await Task.WhenAll(
            MfaFlow.SubmitRecoveryCodeAsync(Stack, a, pageA, code),
            MfaFlow.SubmitRecoveryCodeAsync(Stack, b, pageB, code.ToLowerInvariant().Replace("-", " ", StringComparison.Ordinal)));
        Assert.Equal(1, pages.Count(page => page.Url.AbsolutePath == "/manage"));
        Assert.Equal(1, new[] { a, b }.Count(HasSession));
        Assert.Equal("pwd mfa", (await ActiveSessionAsync(account.User.Id)).Amr);

        // Used once means used: a later attempt with the same code fails, another code works.
        using var later = Stack.NewBrowser();
        var laterPage = await MfaFlow.PasswordStepAsync(Stack, later, account.User);
        var reused = await MfaFlow.SubmitRecoveryCodeAsync(Stack, later, laterPage, code);
        Assert.Equal("/account/recovery", reused.Url.AbsolutePath);
        Assert.False(HasSession(later));
        Assert.Equal("/manage", (await MfaFlow.SubmitRecoveryCodeAsync(Stack, later, laterPage, account.RecoveryCodes[1])).Url.AbsolutePath);
        Assert.Equal(8, await Stack.InIamAsync(services => services.GetRequiredService<MfaService>().RemainingRecoveryCodesAsync(account.User.Id, CancellationToken.None)));
    }

    [Fact]
    public async Task Recovery_Regenerate_InvalidatesEveryOldCode()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, browser, account);

        var settings = await browser.GetAsync($"{Stack.IamOrigin}/manage/mfa");
        var regenerated = await browser.SubmitAsync(settings, "form[action*='handler=Regenerate']");
        var fresh = regenerated.Document.QuerySelectorAll("[data-testid=recovery-codes] li").Select(item => item.TextContent.Trim()).ToList();
        Assert.Equal(10, fresh.Count);
        Assert.Empty(fresh.Intersect(account.RecoveryCodes));

        using var old = Stack.NewBrowser();
        var oldPage = await MfaFlow.PasswordStepAsync(Stack, old, account.User);
        var rejected = await MfaFlow.SubmitRecoveryCodeAsync(Stack, old, oldPage, account.RecoveryCodes[3]);
        Assert.Equal("/account/recovery", rejected.Url.AbsolutePath);
        Assert.False(HasSession(old));
        Assert.Equal("/manage", (await MfaFlow.SubmitRecoveryCodeAsync(Stack, old, oldPage, fresh[0])).Url.AbsolutePath);
    }

    [Fact]
    public async Task Admin_WithoutMfa_CannotOpenTheAdministrationArea_AndCannotBypassIt()
    {
        var admin = await Stack.CreateUserAsync(Roles.PlatformAdmin);
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, admin);

        var denied = await browser.GetAsync($"{Stack.IamOrigin}/admin");
        Assert.Equal("/manage/mfa", denied.Url.AbsolutePath);
        Assert.Contains("Administrators must use two-step sign-in", denied.Text);

        // After enrolling, the same session (which just verified a code) can enter.
        await MfaFlow.EnrollAsync(Stack, browser);
        var allowed = await browser.GetAsync($"{Stack.IamOrigin}/admin");
        Assert.Equal("/admin", allowed.Url.AbsolutePath);
        Assert.Equal(HttpStatusCode.OK, allowed.Status);
    }

    [Fact]
    public async Task Admin_WithMfa_NeedsTheSecondFactorAtEverySignIn()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack, Roles.SecurityAdmin);
        using var browser = Stack.NewBrowser();

        var codePage = await MfaFlow.PasswordStepAsync(Stack, browser, account.User, "/admin");
        Assert.Equal("/account/mfa", codePage.Url.AbsolutePath);
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/admin")).Url.AbsolutePath);

        var landing = await MfaFlow.SubmitCodeAsync(browser, codePage, account.Device.NextCode());
        Assert.Equal("/admin", landing.Url.AbsolutePath);
    }

    [Fact]
    public async Task StepUp_PasswordIsNotAcceptedForAccountsWithMfa_AndReturnUrlMustBeLocal()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, browser, account);

        var stepUp = await browser.GetAsync($"{Stack.IamOrigin}/account/step-up?returnUrl={Uri.EscapeDataString("https://evil.example/")}");
        Assert.Null(stepUp.Find("input[type=password]"));
        var token = stepUp.Find("input[name=__RequestVerificationToken]")!.GetAttribute("value")!;

        // Posting the password handler directly does not step up an MFA account.
        var viaPassword = await browser.PostFormAsync($"{Stack.IamOrigin}/account/step-up?handler=Password",
            [new("password", account.User.Password), new("__RequestVerificationToken", token)]);
        Assert.Equal("/account/step-up", viaPassword.Url.AbsolutePath);
        Assert.Contains("authenticator", viaPassword.Find("[role=alert]")!.TextContent);

        var done = await browser.SubmitAsync(stepUp, "form[action*='handler=Totp']", new Dictionary<string, string> { ["code"] = account.Device.NextCode() });
        Assert.Equal(new Uri(Stack.IamOrigin).Authority, done.Url.Authority);
        Assert.Equal("/manage", done.Url.AbsolutePath);
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class MfaTimeTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private bool HasSession(Browser browser) => browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName) is not null;

    [Fact]
    public async Task Challenge_Expired_CannotBeCompleted()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        var codePage = await MfaFlow.PasswordStepAsync(Stack, browser, account.User);
        Assert.Equal("/account/mfa", codePage.Url.AbsolutePath);

        Stack.Time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        var late = await MfaFlow.SubmitCodeAsync(browser, codePage, account.Device.NextCode());
        Assert.Equal("/account/login", late.Url.AbsolutePath);
        Assert.False(HasSession(browser));
    }

    [Fact]
    public async Task DisableAndRegenerate_NeedARecentSecondFactor_AStaleSessionIsNotEnough()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, browser, account);
        using var other = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, other, account);

        // Six minutes later the session is still valid, but its second factor is no longer "recent".
        Stack.Time.Advance(TimeSpan.FromMinutes(6));
        using var stolen = browser.CloneWithCookies();
        var settings = await stolen.GetAsync($"{Stack.IamOrigin}/manage/mfa");
        Assert.Equal("/manage/mfa", settings.Url.AbsolutePath);

        var remove = await stolen.SubmitAsync(settings, "form[action*='handler=Remove']", new Dictionary<string, string> { ["confirm"] = "true" });
        Assert.Equal("/account/step-up", remove.Url.AbsolutePath);
        var regenerate = await stolen.SubmitAsync(settings, "form[action*='handler=Regenerate']");
        Assert.Equal("/account/step-up", regenerate.Url.AbsolutePath);
        Assert.Empty(regenerate.Document.QuerySelectorAll("[data-testid=recovery-codes] li"));
        var reenroll = await stolen.GetAsync($"{Stack.IamOrigin}/manage/mfa/enroll");
        Assert.Equal("/account/step-up", reenroll.Url.AbsolutePath);

        Assert.True(await Stack.InIamAsync(services => services.GetRequiredService<MfaService>().IsEnabledAsync(account.User.Id, CancellationToken.None)));
        Assert.Equal(10, await Stack.InIamAsync(services => services.GetRequiredService<MfaService>().RemainingRecoveryCodesAsync(account.User.Id, CancellationToken.None)));

        // With a fresh code the owner can turn it off; the other session is signed out and the factor is gone.
        var confirmed = await browser.SubmitAsync(remove, "form[action*='handler=Totp']", new Dictionary<string, string> { ["code"] = account.Device.NextCode() });
        Assert.Equal("/manage/mfa", confirmed.Url.AbsolutePath);
        var removed = await browser.SubmitAsync(confirmed, "form[action*='handler=Remove']", new Dictionary<string, string> { ["confirm"] = "true" });
        Assert.Contains("turned off", removed.Text);
        Assert.False(await Stack.InIamAsync(services => services.GetRequiredService<MfaService>().IsEnabledAsync(account.User.Id, CancellationToken.None)));
        Assert.Equal(0, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().RecoveryCodes.CountAsync(x => x.UserId == account.User.Id)));
        Assert.Equal("/account/login", (await other.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        var session = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.AsNoTracking().SingleAsync(x => x.UserId == account.User.Id && x.RevokedAt == null));
        Assert.Equal("pwd", session.Amr);
        Assert.Null(session.MfaVerifiedAt);
    }

    [Fact]
    public async Task Enrollment_NeedsARecentPassword_ForAccountsWithoutMfa()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, user);
        Stack.Time.Advance(TimeSpan.FromMinutes(6));

        var redirected = await browser.GetAsync($"{Stack.IamOrigin}/manage/mfa/enroll");
        Assert.Equal("/account/step-up", redirected.Url.AbsolutePath);
        Assert.NotNull(redirected.Find("input[type=password]"));

        var wrong = await browser.SubmitAsync(redirected, "form[action*='handler=Password']", new Dictionary<string, string> { ["password"] = "not-the-password" });
        Assert.Equal("/account/step-up", wrong.Url.AbsolutePath);
        Assert.NotNull(wrong.Find("[role=alert]"));

        var enroll = await browser.SubmitAsync(wrong, "form[action*='handler=Password']", new Dictionary<string, string> { ["password"] = user.Password });
        Assert.Equal("/manage/mfa/enroll", enroll.Url.AbsolutePath);
        Assert.NotNull(enroll.Find("[data-testid=totp-secret]"));
    }
}
