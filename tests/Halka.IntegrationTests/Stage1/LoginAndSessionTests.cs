using System.Net;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Pages.Account;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.IntegrationTests.Stage1;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class LoginAndSessionTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private async Task<(Page Page, bool SignedIn)> AttemptAsync(Browser browser, string email, string password)
    {
        var login = await browser.GetAsync($"{Stack.IamOrigin}/account/login");
        var result = await browser.SubmitAsync(login, "form[action*='/account/login']", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });
        return (result, browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName) is not null);
    }

    [Fact]
    public async Task Login_ValidCredentials_StartsSessionWithSecureCookie()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();

        var (page, signedIn) = await AttemptAsync(browser, user.Email, user.Password);

        Assert.True(signedIn);
        Assert.Equal("/manage", page.Url.AbsolutePath);
        Assert.Contains(user.Email, page.Text);
        var cookie = browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!;
        Assert.True(cookie.Secure);
        Assert.True(cookie.HttpOnly);
        Assert.Equal("/", cookie.Path);
        Assert.Contains("no-store", page.Header("Cache-Control"));
    }

    [Fact]
    public async Task Login_GenericError_IsIdenticalForUnknownWrongPasswordLockedOutAndDisabled()
    {
        var user = await Stack.CreateUserAsync();
        var disabled = await Stack.CreateUserAsync();
        var locked = await Stack.CreateUserAsync();
        await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users
            .Where(x => x.Id == disabled.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.IsDisabled, true)));

        using var browser = Stack.NewBrowser();
        var unknown = await AttemptAsync(browser, $"nobody-{Guid.NewGuid():N}@example.test", "some-password-value");
        var wrong = await AttemptAsync(browser, user.Email, "definitely-wrong-password");
        var disabledAttempt = await AttemptAsync(browser, disabled.Email, disabled.Password);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            await AttemptAsync(browser, locked.Email, "definitely-wrong-password");
        }

        var lockedWithCorrectPassword = await AttemptAsync(browser, locked.Email, locked.Password);

        foreach (var (page, signedIn) in new[] { unknown, wrong, disabledAttempt, lockedWithCorrectPassword })
        {
            Assert.False(signedIn);
            Assert.Equal(HttpStatusCode.OK, page.Status);
            Assert.Equal("/account/login", page.Url.AbsolutePath);
            Assert.Equal(LoginModel.GenericError, page.Find("[role=alert]")?.TextContent.Trim());
        }

        var isLockedOut = await Stack.InIamAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            return await users.IsLockedOutAsync((await users.FindByIdAsync(locked.Id.ToString()))!);
        });
        Assert.True(isLockedOut);
    }

    [Fact]
    public async Task Login_RotatesSession_PreviousSessionOfTheBrowserIsEnded()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await AttemptAsync(browser, user.Email, user.Password);
        var firstCookie = browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!.Value;
        using var captured = browser.CloneWithCookies();

        // The same browser authenticates again while still carrying the first session cookie.
        var login = await browser.GetAsync($"{Stack.IamOrigin}/account/login", follow: false);
        Assert.Equal(HttpStatusCode.Redirect, login.Status);
        var second = await browser.PostFormAsync($"{Stack.IamOrigin}/account/login", await LoginFieldsAsync(user), follow: true);

        var secondCookie = browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!.Value;
        Assert.NotEqual(firstCookie, secondCookie);
        Assert.Equal("/manage", second.Url.AbsolutePath);

        var sessions = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions
            .Where(x => x.UserId == user.Id).OrderBy(x => x.CreatedAt).ToListAsync());
        Assert.Equal(2, sessions.Count);
        Assert.Equal(SessionEndReason.Replaced, sessions[0].RevokedReason);
        Assert.Null(sessions[1].RevokedAt);
        Assert.NotEqual(sessions[0].Id, sessions[1].Id);

        // The identifier that existed before the second authentication is dead.
        var replay = await captured.GetAsync($"{Stack.IamOrigin}/manage");
        Assert.Equal("/account/login", replay.Url.AbsolutePath);

        async Task<Dictionary<string, string>> LoginFieldsAsync(TestUser account)
        {
            // A fresh anonymous browser provides a valid form token pair for a manual post with the old cookie attached.
            var form = await browser.GetAsync($"{Stack.IamOrigin}/account/register");
            var token = form.Find("input[name=__RequestVerificationToken]")!.GetAttribute("value")!;
            return new Dictionary<string, string>
            {
                ["Input.Email"] = account.Email,
                ["Input.Password"] = account.Password,
                ["__RequestVerificationToken"] = token,
            };
        }
    }

    [Fact]
    public async Task Session_CapturedCookieAfterLogout_IsDenied()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var account = (await AttemptAsync(browser, user.Email, user.Password)).Page;
        using var attacker = browser.CloneWithCookies();
        Assert.Equal("/manage", (await attacker.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        var signedOut = await browser.SubmitAsync(account, "form[action*='/account/logout']", follow: false);

        Assert.Equal(HttpStatusCode.Redirect, signedOut.Status);
        Assert.Equal("\"cache\"", signedOut.Header("Clear-Site-Data"));
        Assert.Null(browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

        // The attacker still holds a cryptographically valid, unexpired cookie. Only server state rejects it.
        var replay = await attacker.GetAsync($"{Stack.IamOrigin}/manage", follow: false);
        Assert.Equal(HttpStatusCode.Redirect, replay.Status);
        Assert.StartsWith("/account/login", new Uri(new Uri(Stack.IamOrigin), replay.Response.Headers.Location!).PathAndQuery);

        var api = await attacker.GetAsync($"{Stack.IamOrigin}/api/account/session", follow: false);
        Assert.Equal(HttpStatusCode.Unauthorized, api.Status);
        Assert.Equal("application/problem+json", api.Response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Session_DisabledUser_IsDeniedOnNextRequestAndCannotSignInAgain()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await AttemptAsync(browser, user.Email, user.Password);
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users
            .Where(x => x.Id == user.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.IsDisabled, true)));

        var denied = await browser.GetAsync($"{Stack.IamOrigin}/manage");
        Assert.Equal("/account/login", denied.Url.AbsolutePath);

        using var fresh = Stack.NewBrowser();
        var (page, signedIn) = await AttemptAsync(fresh, user.Email, user.Password);
        Assert.False(signedIn);
        Assert.Equal(LoginModel.GenericError, page.Find("[role=alert]")?.TextContent.Trim());
    }

    [Theory]
    [InlineData("https://evil.example/steal")]
    [InlineData("//evil.example/steal")]
    [InlineData("/\\evil.example/steal")]
    [InlineData("javascript:alert(1)")]
    public async Task ReturnUrl_NonLocalTarget_IsNotFollowed(string returnUrl)
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();

        var landing = await Stack.SignInAsync(browser, user, returnUrl);

        Assert.Equal(new Uri(Stack.IamOrigin).Authority, landing.Url.Authority);
        Assert.Equal("/manage", landing.Url.AbsolutePath);
        Assert.DoesNotContain(landing.Visited, uri => uri.Host.Contains("evil", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReturnUrl_LocalPath_IsFollowed()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();

        var landing = await Stack.SignInAsync(browser, user, "/manage/sessions");

        Assert.Equal("/manage/sessions", landing.Url.AbsolutePath);
    }

    [Fact]
    public async Task Csrf_LoginAndLogoutPostsWithoutToken_AreRejected()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();

        var forgedLogin = await browser.PostFormAsync($"{Stack.IamOrigin}/account/login",
        [
            new("Input.Email", user.Email),
            new("Input.Password", user.Password),
        ]);
        Assert.Equal(HttpStatusCode.BadRequest, forgedLogin.Status);
        Assert.Null(browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

        await Stack.SignInAsync(browser, user);
        var forgedLogout = await browser.PostFormAsync($"{Stack.IamOrigin}/account/logout", []);
        Assert.Equal(HttpStatusCode.BadRequest, forgedLogout.Status);
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // A token that belongs to another browser's anti-forgery cookie is not accepted either.
        using var other = Stack.NewBrowser();
        var foreignForm = await other.GetAsync($"{Stack.IamOrigin}/account/login");
        var foreignToken = foreignForm.Find("input[name=__RequestVerificationToken]")!.GetAttribute("value")!;
        var crossed = await browser.PostFormAsync($"{Stack.IamOrigin}/account/logout", [new("__RequestVerificationToken", foreignToken)]);
        Assert.Equal(HttpStatusCode.BadRequest, crossed.Status);
    }

    [Fact]
    public async Task Idor_AnotherUsersSession_CannotBeRevokedThroughPageOrApi()
    {
        var victim = await Stack.CreateUserAsync();
        var attacker = await Stack.CreateUserAsync();
        using var victimBrowser = Stack.NewBrowser();
        using var attackerBrowser = Stack.NewBrowser();
        await Stack.SignInAsync(victimBrowser, victim);
        await Stack.SignInAsync(attackerBrowser, attacker);
        var victimSession = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions
            .Where(x => x.UserId == victim.Id && x.RevokedAt == null).Select(x => x.Id).SingleAsync());

        var sessionsPage = await attackerBrowser.GetAsync($"{Stack.IamOrigin}/manage/sessions");
        var viaPage = await attackerBrowser.SubmitAsync(sessionsPage, "form[action*='handler=Revoke']:not([action*='RevokeAll'])",
            new Dictionary<string, string> { ["id"] = victimSession.ToString() });
        Assert.Equal(HttpStatusCode.NotFound, viaPage.Status);

        var token = sessionsPage.Find("input[name=__RequestVerificationToken]")!.GetAttribute("value")!;
        var viaApi = await attackerBrowser.SendAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Delete, $"{Stack.IamOrigin}/api/account/sessions/{victimSession}");
            request.Headers.Add("X-CSRF-TOKEN", token);
            return request;
        });
        Assert.Equal(HttpStatusCode.NotFound, viaApi.Status);

        Assert.Equal("/manage", (await victimBrowser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
    }

    [Fact]
    public async Task Session_UserCanRevokeOwnOtherSession_AndSignOutEverywhere()
    {
        var user = await Stack.CreateUserAsync();
        using var laptop = Stack.NewBrowser();
        using var phone = Stack.NewBrowser();
        await Stack.SignInAsync(laptop, user);
        Stack.Time.Advance(TimeSpan.FromSeconds(1));
        await Stack.SignInAsync(phone, user);
        var phoneSession = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions
            .Where(x => x.UserId == user.Id && x.RevokedAt == null).OrderByDescending(x => x.CreatedAt).Select(x => x.Id).FirstAsync());

        var sessionsPage = await laptop.GetAsync($"{Stack.IamOrigin}/manage/sessions");
        Assert.Equal(2, sessionsPage.Document.QuerySelectorAll("table.data tbody tr").Length);
        var afterRevoke = await laptop.SubmitAsync(sessionsPage, "form[action*='handler=Revoke']:not([action*='RevokeAll'])",
            new Dictionary<string, string> { ["id"] = phoneSession.ToString() });

        Assert.Equal("/manage/sessions", afterRevoke.Url.AbsolutePath);
        Assert.Single(afterRevoke.Document.QuerySelectorAll("table.data tbody tr"));
        Assert.Equal("/account/login", (await phone.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        using var captured = laptop.CloneWithCookies();
        var everywhere = await laptop.SubmitAsync(afterRevoke, "form[action*='handler=RevokeAll']");
        Assert.Equal("/account/login", everywhere.Url.AbsolutePath);
        Assert.Equal("/account/login", (await captured.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
    }

    [Fact]
    public async Task Admin_AreaRequiresAdministrativeRole_AndRoleRemovalAppliesImmediately()
    {
        var regular = await Stack.CreateUserAsync();

        // Administrators must have a second factor (stage 5), so the administrator signs in with one.
        var adminAccount = await MfaFlow.CreateAccountAsync(Stack, Roles.SecurityAdmin);
        var admin = adminAccount.User;
        using var regularBrowser = Stack.NewBrowser();
        using var adminBrowser = Stack.NewBrowser();
        await Stack.SignInAsync(regularBrowser, regular);
        await MfaFlow.SignInAsync(Stack, adminBrowser, adminAccount);

        var denied = await regularBrowser.GetAsync($"{Stack.IamOrigin}/admin");
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("/account/access-denied", denied.Url.AbsolutePath);

        var allowed = await adminBrowser.GetAsync($"{Stack.IamOrigin}/admin");
        Assert.Equal(HttpStatusCode.OK, allowed.Status);
        Assert.Equal("/admin", allowed.Url.AbsolutePath);

        // The role is removed in the database; the admin keeps the very same cookie.
        await Stack.InIamAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var entity = (await users.FindByIdAsync(admin.Id.ToString()))!;
            Assert.True((await users.RemoveFromRoleAsync(entity, Roles.SecurityAdmin)).Succeeded);
        });

        var afterRemoval = await adminBrowser.GetAsync($"{Stack.IamOrigin}/admin");
        Assert.Equal(HttpStatusCode.Forbidden, afterRemoval.Status);
    }

    [Fact]
    public async Task Anonymous_ProtectedPages_RedirectToLoginWithLocalReturnUrl()
    {
        using var browser = Stack.NewBrowser();

        var response = await browser.GetAsync($"{Stack.IamOrigin}/manage/sessions", follow: false);

        Assert.Equal(HttpStatusCode.Redirect, response.Status);
        var location = new Uri(new Uri(Stack.IamOrigin), response.Response.Headers.Location!);
        Assert.Equal("/account/login", location.AbsolutePath);
        Assert.Contains("returnUrl=%2Fmanage%2Fsessions", location.Query, StringComparison.OrdinalIgnoreCase);
    }
}
