using System.Net;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mail;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.IntegrationTests.Stage1;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class SignupAndMailSinkTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private async Task<Page> RegisterAsync(Browser browser, string email, string password, Dictionary<string, string>? extra = null)
    {
        var form = await browser.GetAsync($"{Stack.IamOrigin}/account/register");
        var fields = new Dictionary<string, string>
        {
            ["Input.DisplayName"] = "New Person",
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        };
        foreach (var (key, value) in extra ?? [])
        {
            fields[key] = value;
        }

        return await browser.SubmitAsync(form, "form[action*='/account/register']", fields);
    }

    [Fact]
    public async Task Signup_ConfirmationThroughPrivateSink_ThenLoginWorks_AndOnlyUserRoleIsGranted()
    {
        var email = $"signup-{Guid.NewGuid():N}@example.test";
        var password = $"Pw-{Guid.NewGuid():N}";
        using var browser = Stack.NewBrowser();

        // Attempts to smuggle privileged fields are ignored: the form model has no such properties.
        var submitted = await RegisterAsync(browser, email, password, new Dictionary<string, string>
        {
            ["Input.Role"] = Roles.PlatformAdmin,
            ["Role"] = Roles.PlatformAdmin,
            ["Input.EmailConfirmed"] = "true",
            ["Input.IsDisabled"] = "false",
        });
        Assert.Equal(HttpStatusCode.OK, submitted.Status);
        Assert.Contains("Check the demo mail sink", submitted.Text);

        // Before confirmation the account cannot sign in.
        var early = await Stack.SignInAsync(browser, new TestUser(Guid.Empty, email, "New Person", password));
        Assert.Equal("/account/login", early.Url.AbsolutePath);
        Assert.Null(browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

        var mail = await Stack.ReceiveMailAsync(email, MailKind.ConfirmEmail);
        Assert.StartsWith($"{Stack.IamOrigin}/account/confirm-email?token=", mail.Link);
        Assert.DoesNotContain(new Uri(mail.Link).Query.Split('=')[1], submitted.Body);

        var confirm = await browser.GetAsync(mail.Link);
        var confirmed = await browser.SubmitAsync(confirm, "form[action*='/account/confirm-email']");
        Assert.Equal("/account/login", confirmed.Url.AbsolutePath);
        Assert.Contains("confirmed", confirmed.Text);

        var landing = await Stack.SignInAsync(browser, new TestUser(Guid.Empty, email, "New Person", password));
        Assert.Equal("/manage", landing.Url.AbsolutePath);

        var (roles, emailConfirmed) = await Stack.InIamAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByEmailAsync(email))!;
            return (await users.GetRolesAsync(user), user.EmailConfirmed);
        });
        Assert.Equal([Roles.User], roles);
        Assert.True(emailConfirmed);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync($"{Stack.IamOrigin}/admin")).Status);
    }

    [Fact]
    public async Task Signup_ConfirmationToken_IsSingleUse()
    {
        var email = $"signup-{Guid.NewGuid():N}@example.test";
        using var browser = Stack.NewBrowser();
        await RegisterAsync(browser, email, $"Pw-{Guid.NewGuid():N}");
        var mail = await Stack.ReceiveMailAsync(email, MailKind.ConfirmEmail);

        var first = await browser.SubmitAsync(await browser.GetAsync(mail.Link), "form[action*='/account/confirm-email']");
        var second = await browser.SubmitAsync(await browser.GetAsync(mail.Link), "form[action*='/account/confirm-email']");

        Assert.Equal("/account/login", first.Url.AbsolutePath);
        Assert.Equal("/account/confirm-email", second.Url.AbsolutePath);
        Assert.Contains("not valid any more", second.Text);
    }

    [Fact]
    public async Task Signup_ExistingAddress_GetsTheSameResponse_AndNoSecondAccountOrMail()
    {
        var existing = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var fresh = await RegisterAsync(browser, $"signup-{Guid.NewGuid():N}@example.test", $"Pw-{Guid.NewGuid():N}");

        var duplicate = await RegisterAsync(browser, existing.Email, $"Pw-{Guid.NewGuid():N}");

        Assert.Equal(fresh.Status, duplicate.Status);
        Assert.Equal(fresh.Find("[role=status]")?.TextContent.Trim(), duplicate.Find("[role=status]")?.TextContent.Trim());
        await Stack.DispatchMailAsync();
        Assert.DoesNotContain(Stack.ReadMailSink(), mail => mail.To == existing.Email);
        var count = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.CountAsync(x => x.Email == existing.Email));
        Assert.Equal(1, count);

        // The original password still works: the duplicate request did not touch the account.
        Assert.Equal("/manage", (await Stack.SignInAsync(browser, existing)).Url.AbsolutePath);
    }

    [Fact]
    public async Task Signup_WeakPassword_IsRejectedWithoutCreatingAnAccount()
    {
        var email = $"signup-{Guid.NewGuid():N}@example.test";
        using var browser = Stack.NewBrowser();

        var result = await RegisterAsync(browser, email, "short");

        Assert.NotNull(result.Find("[role=alert]"));
        Assert.Equal(0, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.CountAsync(x => x.Email == email)));
    }

    [Fact]
    public async Task MailSink_IsNotReachableOverHttp_AndTokensAreStoredOnlyAsHashes()
    {
        var email = $"signup-{Guid.NewGuid():N}@example.test";
        using var browser = Stack.NewBrowser();
        await RegisterAsync(browser, email, $"Pw-{Guid.NewGuid():N}");
        var mail = await Stack.ReceiveMailAsync(email, MailKind.ConfirmEmail);
        var rawToken = Uri.UnescapeDataString(new Uri(mail.Link).Query["?token=".Length..]);

        var admin = await Stack.CreateUserAsync(Roles.PlatformAdmin);
        using var adminBrowser = Stack.NewBrowser();
        await Stack.SignInAsync(adminBrowser, admin);
        foreach (var path in new[] { "/mail", "/mail-sink", "/admin/mail", "/admin/mail-sink", "/dev/mail", "/assets/mail-sink", $"/assets/{mail.MessageId}.json", "/api/mail" })
        {
            foreach (var agent in new[] { browser, adminBrowser })
            {
                var response = await agent.GetAsync($"{Stack.IamOrigin}{path}");
                Assert.Equal(HttpStatusCode.NotFound, response.Status);
                Assert.DoesNotContain(rawToken, response.Body);
            }
        }

        // Nothing in the database contains the raw token: the token row stores a hash, the outbox payload is encrypted,
        // and audit rows carry identifiers only.
        await Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            var tokens = await db.OneTimeTokens.AsNoTracking().ToListAsync();
            Assert.All(tokens, token => Assert.Equal(32, token.TokenHash.Length));
            var outbox = await db.OutboxMessages.AsNoTracking().ToListAsync();
            Assert.All(outbox, message => Assert.DoesNotContain(rawToken, System.Text.Encoding.UTF8.GetString(message.ProtectedPayload)));
            Assert.All(outbox, message => Assert.DoesNotContain(email, System.Text.Encoding.UTF8.GetString(message.ProtectedPayload)));
            var audit = await db.AuditEvents.AsNoTracking().ToListAsync();
            Assert.All(audit, entry =>
            {
                var row = $"{entry.ActorId}|{entry.TargetId}|{entry.Reason}|{entry.Action}";
                Assert.DoesNotContain(rawToken, row);
                Assert.DoesNotContain(email, row);
            });
            return true;
        });

        Assert.DoesNotContain(Stack.Logs.Lines, line => line.Contains(rawToken, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Health_OpenApi_AndSecurityHeaders_ArePresent()
    {
        using var browser = Stack.NewBrowser();

        var live = await browser.GetAsync($"{Stack.IamOrigin}/health/live");
        var ready = await browser.GetAsync($"{Stack.IamOrigin}/health/ready");
        var openApi = await browser.GetAsync($"{Stack.IamOrigin}/openapi/v1.json");
        var login = await browser.GetAsync($"{Stack.IamOrigin}/account/login");
        var css = await browser.GetAsync($"{Stack.IamOrigin}/assets/site.css");

        Assert.Equal(HttpStatusCode.OK, live.Status);
        Assert.Equal(HttpStatusCode.OK, ready.Status);
        Assert.Contains("Healthy", ready.Body);
        Assert.Equal(HttpStatusCode.OK, openApi.Status);
        Assert.Contains("/api/account/session", openApi.Body);

        Assert.Equal("nosniff", login.Header("X-Content-Type-Options"));
        Assert.Equal("DENY", login.Header("X-Frame-Options"));
        Assert.Equal("no-referrer", login.Header("Referrer-Policy"));
        var csp = login.Header("Content-Security-Policy")!;
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.DoesNotContain("http:", csp);
        Assert.Null(login.Header("Server"));

        // The sign-in page loads nothing from another origin and has no inline script or style.
        Assert.All(login.Document.QuerySelectorAll("script[src], link[href], img[src]"), element =>
        {
            var reference = element.GetAttribute("src") ?? element.GetAttribute("href")!;
            Assert.StartsWith("/", reference);
            Assert.False(reference.StartsWith("//", StringComparison.Ordinal));
        });
        Assert.Empty(login.Document.QuerySelectorAll("script:not([src]), style, [style]"));
        Assert.Equal(HttpStatusCode.OK, css.Status);
        Assert.Contains("max-age", css.Header("Cache-Control"));
    }
}
