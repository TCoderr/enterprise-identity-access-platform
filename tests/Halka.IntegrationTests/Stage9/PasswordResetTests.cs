using System.Net;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mail;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Halka.IntegrationTests.Stage9;

internal static class ResetFlow
{
    public const string FormSelector = "form[action*='/account/reset-password']";

    /// <summary>Submits the forgot-password form and returns the response with the mail it produced (if any).</summary>
    public static async Task<(Page Response, SinkMail? Mail)> RequestAsync(HalkaStack stack, Browser browser, string email)
    {
        await stack.DrainMailAsync();
        var known = stack.ReadMailSink().Select(mail => mail.MessageId).ToHashSet(StringComparer.Ordinal);
        var form = await browser.GetAsync($"{stack.IamOrigin}/account/forgot-password");
        var response = await browser.SubmitAsync(form, "form[action*='/account/forgot-password']", new Dictionary<string, string> { ["Email"] = email });
        await stack.DrainMailAsync();
        var mail = stack.ReadMailSink().SingleOrDefault(candidate => !known.Contains(candidate.MessageId) && candidate.Kind == MailKind.ResetPassword);
        return (response, mail);
    }

    public static Task<Page> SubmitAsync(Browser browser, Page form, string newPassword)
        => browser.SubmitAsync(form, FormSelector, new Dictionary<string, string> { ["NewPassword"] = newPassword });

    public static string RawToken(SinkMail mail) => Uri.UnescapeDataString(new Uri(mail.Link).Query["?token=".Length..]);

    public static string NewPassword() => $"Nw-{Guid.NewGuid():N}";

    public static bool IsInvalidLinkPage(Page page)
        => page.Url.AbsolutePath == "/account/reset-password" && page.Text.Contains("not valid any more", StringComparison.Ordinal);
}

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class PasswordResetTests(StackFixture fixture)
{
    private const string Scopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    private async Task<bool> CanSignInAsync(TestUser user, string password)
    {
        using var browser = Stack.NewBrowser();
        return (await Stack.SignInAsync(browser, user with { Password = password })).Url.AbsolutePath == "/manage";
    }

    [Fact]
    public async Task Reset_ChangesThePassword_EndsEverySessionAndGrant_AndDoesNotSignAnyoneIn()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, Scopes);
        using var second = Stack.NewBrowser();
        await Stack.SignInAsync(second, user);

        using var recovery = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, recovery, user.Email);
        Assert.NotNull(mail);
        Assert.Equal(user.Email, mail.To);
        Assert.StartsWith($"{Stack.IamOrigin}/account/reset-password?token=", mail.Link);

        // Asking for a link changes nothing: sessions, tokens and the password stay as they were.
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.True((await pano.IntrospectAsync(tokens.AccessToken)).Json.GetProperty("active").GetBoolean());

        var form = await recovery.GetAsync(mail.Link);
        Assert.Equal("no-referrer", form.Header("Referrer-Policy"));
        Assert.Contains("no-store", form.Header("Cache-Control"));
        var newPassword = ResetFlow.NewPassword();
        var done = await ResetFlow.SubmitAsync(recovery, form, newPassword);

        Assert.Equal("/account/login", done.Url.AbsolutePath);
        Assert.Contains("Your password was changed", done.Text);
        Assert.Null(recovery.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

        // Every central session is over and every token issued from them is dead.
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.Equal("/account/login", (await second.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        Assert.False((await pano.IntrospectAsync(tokens.AccessToken)).Json.GetProperty("active").GetBoolean());
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(tokens.RefreshToken)).Error);
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);

        Assert.False(await CanSignInAsync(user, user.Password));
        Assert.True(await CanSignInAsync(user, newPassword));

        var rawToken = ResetFlow.RawToken(mail);
        await Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            var audit = await db.AuditEvents.AsNoTracking().Where(x => x.TargetId == user.Id.ToString()).ToListAsync();
            Assert.Contains(audit, entry => entry.Action == "account.password_reset" && entry.Outcome == "success");
            Assert.Contains(audit, entry => entry.Action == "session.ended_all" && entry.Reason!.StartsWith($"{SessionEndReason.PasswordReset}; sessions=2; grants=1", StringComparison.Ordinal));
            Assert.All(audit, entry => Assert.DoesNotContain(rawToken, $"{entry.Reason}|{entry.ActorId}|{entry.TargetId}"));
            Assert.All(await db.OneTimeTokens.AsNoTracking().Where(x => x.UserId == user.Id).ToListAsync(), token => Assert.NotNull(token.ConsumedAt));
        });
        var logs = string.Join('\n', Stack.Logs.Lines);
        Assert.DoesNotContain(rawToken, logs);
        Assert.DoesNotContain(newPassword, logs);
    }

    [Fact]
    public async Task Reset_Link_IsSingleUse_AndAReplayChangesNothing()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var replay = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, browser, user.Email);
        var firstForm = await browser.GetAsync(mail!.Link);
        var replayForm = await replay.GetAsync(mail.Link);
        var firstPassword = ResetFlow.NewPassword();
        var replayPassword = ResetFlow.NewPassword();

        var first = await ResetFlow.SubmitAsync(browser, firstForm, firstPassword);
        var replayed = await ResetFlow.SubmitAsync(replay, replayForm, replayPassword);
        var reopened = await replay.GetAsync(mail.Link);

        Assert.Equal("/account/login", first.Url.AbsolutePath);
        Assert.True(ResetFlow.IsInvalidLinkPage(replayed));
        Assert.True(ResetFlow.IsInvalidLinkPage(reopened));
        Assert.Null(reopened.Find(ResetFlow.FormSelector));
        Assert.True(await CanSignInAsync(user, firstPassword));
        Assert.False(await CanSignInAsync(user, replayPassword));
    }

    [Fact]
    public async Task Reset_ConcurrentUseOfOneLink_ExactlyOneRequestWins()
    {
        var user = await Stack.CreateUserAsync();
        using var requester = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, requester, user.Email);

        // Four user agents open the same link (opening does not consume it) and submit at the same time.
        var agents = Enumerable.Range(0, 4).Select(_ => Stack.NewBrowser()).ToList();
        try
        {
            var forms = new List<Page>();
            foreach (var agent in agents)
            {
                forms.Add(await agent.GetAsync(mail!.Link));
            }

            var passwords = agents.Select(_ => ResetFlow.NewPassword()).ToList();
            var results = await Task.WhenAll(agents.Select((agent, index) => ResetFlow.SubmitAsync(agent, forms[index], passwords[index])));

            var winners = results.Select((page, index) => (page, index)).Where(x => x.page.Url.AbsolutePath == "/account/login").ToList();
            Assert.Single(winners);
            Assert.Equal(3, results.Count(ResetFlow.IsInvalidLinkPage));

            // The stored password is the winner's and nobody else's.
            var winner = winners[0].index;
            Assert.True(await CanSignInAsync(user, passwords[winner]));
            Assert.False(await CanSignInAsync(user, passwords[(winner + 1) % passwords.Count]));
            var resets = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents
                .CountAsync(x => x.TargetId == user.Id.ToString() && x.Action == "account.password_reset"));
            Assert.Equal(1, resets);
        }
        finally
        {
            agents.ForEach(agent => agent.Dispose());
        }
    }

    [Fact]
    public async Task Reset_WeakPassword_IsRejected_AndTheLinkCanStillBeUsed()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, browser, user.Email);
        var form = await browser.GetAsync(mail!.Link);

        var rejected = await ResetFlow.SubmitAsync(browser, form, "short");

        Assert.Equal("/account/reset-password", rejected.Url.AbsolutePath);
        Assert.NotNull(rejected.Find("[role=alert]"));
        Assert.NotNull(rejected.Find(ResetFlow.FormSelector));
        Assert.True(await CanSignInAsync(user, user.Password));

        var newPassword = ResetFlow.NewPassword();
        var accepted = await ResetFlow.SubmitAsync(browser, rejected, newPassword);
        Assert.Equal("/account/login", accepted.Url.AbsolutePath);
        Assert.True(await CanSignInAsync(user, newPassword));
    }

    [Fact]
    public async Task Reset_NewRequest_InvalidatesTheOlderLink()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var (_, older) = await ResetFlow.RequestAsync(Stack, browser, user.Email);
        var (_, newer) = await ResetFlow.RequestAsync(Stack, browser, user.Email);
        Assert.NotEqual(older!.Link, newer!.Link);

        Assert.True(ResetFlow.IsInvalidLinkPage(await browser.GetAsync(older.Link)));
        var newPassword = ResetFlow.NewPassword();
        var done = await ResetFlow.SubmitAsync(browser, await browser.GetAsync(newer.Link), newPassword);

        Assert.Equal("/account/login", done.Url.AbsolutePath);
        Assert.True(await CanSignInAsync(user, newPassword));
    }

    [Fact]
    public async Task Reset_Request_AnswersTheSameForEveryAddress_AndOnlyEligibleAccountsGetMail()
    {
        var eligible = await Stack.CreateUserAsync();
        var disabled = await Stack.CreateUserAsync();
        var unconfirmed = await Stack.CreateUserAsync();
        await Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            await db.Users.Where(x => x.Id == disabled.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.IsDisabled, true));
            await db.Users.Where(x => x.Id == unconfirmed.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.EmailConfirmed, false));
        });
        using var browser = Stack.NewBrowser();

        var known = await ResetFlow.RequestAsync(Stack, browser, eligible.Email);
        var unknown = await ResetFlow.RequestAsync(Stack, browser, $"nobody-{Guid.NewGuid():N}@example.test");
        var forDisabled = await ResetFlow.RequestAsync(Stack, browser, disabled.Email);
        var forUnconfirmed = await ResetFlow.RequestAsync(Stack, browser, unconfirmed.Email);

        Assert.NotNull(known.Mail);
        foreach (var other in new[] { unknown, forDisabled, forUnconfirmed })
        {
            Assert.Null(other.Mail);
            Assert.Equal(known.Response.Status, other.Response.Status);
            Assert.Equal(known.Response.Url.AbsolutePath, other.Response.Url.AbsolutePath);
            Assert.Equal(known.Response.Find("main")!.TextContent.Trim(), other.Response.Find("main")!.TextContent.Trim());
        }

        Assert.DoesNotContain(Stack.ReadMailSink(), mail => mail.To == disabled.Email || mail.To == unconfirmed.Email);
    }

    [Fact]
    public async Task Reset_AccountDisabledAfterTheRequest_CannotCompleteIt()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, browser, user.Email);
        var form = await browser.GetAsync(mail!.Link);
        var hashBefore = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == user.Id).Select(x => x.PasswordHash).SingleAsync());
        await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == user.Id)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.IsDisabled, true)));

        var result = await ResetFlow.SubmitAsync(browser, form, ResetFlow.NewPassword());

        Assert.True(ResetFlow.IsInvalidLinkPage(result));
        var hashAfter = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == user.Id).Select(x => x.PasswordHash).SingleAsync());
        Assert.Equal(hashBefore, hashAfter);
    }

    [Fact]
    public async Task Reset_KeepsTheSecondFactor_SoAStolenMailboxAloneCannotSignIn()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, browser, account.User.Email);
        var newPassword = ResetFlow.NewPassword();
        var done = await ResetFlow.SubmitAsync(browser, await browser.GetAsync(mail!.Link), newPassword);
        Assert.Equal("/account/login", done.Url.AbsolutePath);

        // The new password alone gets no session: the authenticator is still required.
        var changed = account with { User = account.User with { Password = newPassword } };
        var codePage = await MfaFlow.PasswordStepAsync(Stack, browser, changed.User);
        Assert.Equal("/account/mfa", codePage.Url.AbsolutePath);
        Assert.Null(browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

        var landing = await MfaFlow.SubmitCodeAsync(browser, codePage, account.Device.NextCode());
        Assert.Equal("/manage", landing.Url.AbsolutePath);
        var (status, codes) = await Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            return (await db.UserMfa.Where(x => x.UserId == account.User.Id).Select(x => x.Status).SingleAsync(),
                await db.RecoveryCodes.CountAsync(x => x.UserId == account.User.Id));
        });
        Assert.Equal(MfaStatus.Active, status);
        Assert.Equal(account.RecoveryCodes.Count, codes);
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class OneTimeLinkExpiryTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Reset_Link_WorksUntilItsLifetimeEnds_AndNotAfter()
    {
        var lifetime = await Stack.InIamAsync(services => Task.FromResult(services.GetRequiredService<IOptions<IamOptions>>().Value.PasswordResetLifetime));
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        var (_, mail) = await ResetFlow.RequestAsync(Stack, browser, user.Email);

        Stack.Time.Advance(lifetime - TimeSpan.FromSeconds(1));
        var form = await browser.GetAsync(mail!.Link);
        Assert.NotNull(form.Find(ResetFlow.FormSelector));

        Stack.Time.Advance(TimeSpan.FromSeconds(1));
        var late = await ResetFlow.SubmitAsync(browser, form, ResetFlow.NewPassword());
        var reopened = await browser.GetAsync(mail.Link);

        Assert.True(ResetFlow.IsInvalidLinkPage(late));
        Assert.True(ResetFlow.IsInvalidLinkPage(reopened));
        using var signIn = Stack.NewBrowser();
        Assert.Equal("/manage", (await Stack.SignInAsync(signIn, user)).Url.AbsolutePath);
    }

    [Fact]
    public async Task Confirmation_Link_ExpiresAfterItsLifetime()
    {
        var lifetime = await Stack.InIamAsync(services => Task.FromResult(services.GetRequiredService<IOptions<IamOptions>>().Value.EmailConfirmationLifetime));
        var email = $"signup-{Guid.NewGuid():N}@example.test";
        var password = ResetFlow.NewPassword();
        using var browser = Stack.NewBrowser();
        var register = await browser.GetAsync($"{Stack.IamOrigin}/account/register");
        await browser.SubmitAsync(register, "form[action*='/account/register']", new Dictionary<string, string>
        {
            ["Input.DisplayName"] = "Late Person",
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });
        var mail = await Stack.ReceiveMailAsync(email, MailKind.ConfirmEmail);
        var confirm = await browser.GetAsync(mail.Link);

        Stack.Time.Advance(lifetime);
        var late = await browser.SubmitAsync(confirm, "form[action*='/account/confirm-email']");

        Assert.Equal("/account/confirm-email", late.Url.AbsolutePath);
        Assert.Contains("not valid any more", late.Text);
        var confirmed = await Stack.InIamAsync(async services => (await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email))!.EmailConfirmed);
        Assert.False(confirmed);
    }
}
