using System.Net;
using Halka.Iam.Data;
using Halka.Iam.Sessions;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.IntegrationTests.Stage9;

/// <summary>
/// A stack with small limits. Every test talks from its own loopback address, so the per-address budgets of the
/// tests are independent of each other and of the order they run in.
/// </summary>
public sealed class RateLimitFixture : StackFixture
{
    public const int Account = 3;
    public const int Address = 20;
    public const int Mfa = 3;
    public const int Recovery = 2;
    public const int Signup = 2;
    public const int Token = 5;

    protected override StackOptions Options
    {
        get
        {
            var options = new StackOptions();
            options.IamSettings["RateLimits:LoginPerAccountPerMinute"] = Account.ToString();
            options.IamSettings["RateLimits:LoginPerAddressPerMinute"] = Address.ToString();
            options.IamSettings["RateLimits:MfaPerMinute"] = Mfa.ToString();
            options.IamSettings["RateLimits:RecoveryPerMinute"] = Recovery.ToString();
            options.IamSettings["RateLimits:SignupPerHour"] = Signup.ToString();
            options.IamSettings["RateLimits:TokenPerMinute"] = Token.ToString();
            return options;
        }
    }
}

[CollectionDefinition(Name)]
public sealed class RateLimitCollection : ICollectionFixture<RateLimitFixture>
{
    public const string Name = "rate-limit";
}

[Collection(RateLimitCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class RateLimitTests(RateLimitFixture fixture)
{
    private const string LoginForm = "form[action*='/account/login']";

    private HalkaStack Stack => fixture.Stack;

    private static IPAddress From(int lastOctet) => new([127, 0, 0, (byte)lastOctet]);

    /// <summary>
    /// Repeats an attempt until it is throttled and returns how many were let through. The windows run on the wall
    /// clock, so one window change may fall inside a test; that can only add one more budget, never remove one.
    /// </summary>
    private static async Task<(int Allowed, T Throttled)> UntilThrottledAsync<T>(int limit, Func<int, Task<T>> attempt, Func<T, bool> isThrottled)
    {
        for (var number = 1; number <= (2 * limit) + 1; number++)
        {
            var result = await attempt(number);
            if (isThrottled(result))
            {
                Assert.InRange(number - 1, limit, 2 * limit);
                return (number - 1, result);
            }
        }

        throw new Xunit.Sdk.XunitException($"No request was throttled after {(2 * limit) + 1} attempts (limit {limit}).");
    }

    private static bool IsPlainRejection(Page page)
        => page.Status == HttpStatusCode.TooManyRequests && page.Body.StartsWith("Too many requests", StringComparison.Ordinal);

    private static void AssertRetryAfter(string? header)
    {
        Assert.True(int.TryParse(header, out var seconds), $"Retry-After is not a number of seconds: '{header}'.");
        Assert.InRange(seconds, 1, 3600);
    }

    private static Task<Page> PostLoginAsync(Browser browser, Page login, string email, string password)
        => browser.SubmitAsync(login, LoginForm, new Dictionary<string, string> { ["Input.Email"] = email, ["Input.Password"] = password }, follow: false);

    [Fact]
    public async Task Login_PerAccountLimit_ThrottlesGuessing_WithoutRevealingAccounts_OrBlockingOthers()
    {
        var target = await Stack.CreateUserAsync();
        var bystander = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser(From(11));
        var login = await browser.GetAsync($"{Stack.IamOrigin}/account/login");

        var guessing = await UntilThrottledAsync(
            RateLimitFixture.Account,
            number => PostLoginAsync(browser, login, target.Email, $"wrong-guess-{number}"),
            page => page.Status == HttpStatusCode.TooManyRequests);
        Assert.Contains("Too many sign-in attempts", guessing.Throttled.Text);

        // While throttled the correct password is not even evaluated, so the limit cannot be used as an oracle.
        var correct = await PostLoginAsync(browser, login, target.Email, target.Password);
        Assert.Equal(HttpStatusCode.TooManyRequests, correct.Status);
        Assert.Null(browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

        // An address that does not belong to any account is throttled in exactly the same way.
        var unknown = $"nobody-{Guid.NewGuid():N}@example.test";
        var probing = await UntilThrottledAsync(
            RateLimitFixture.Account,
            number => PostLoginAsync(browser, login, unknown, $"wrong-guess-{number}"),
            page => page.Status == HttpStatusCode.TooManyRequests);
        Assert.Equal(guessing.Throttled.Find("[role=alert]")!.TextContent.Trim(), probing.Throttled.Find("[role=alert]")!.TextContent.Trim());

        // Another account is not affected, from the same address ...
        var other = await browser.SubmitAsync(login, LoginForm, new Dictionary<string, string> { ["Input.Email"] = bystander.Email, ["Input.Password"] = bystander.Password });
        Assert.Equal("/manage", other.Url.AbsolutePath);

        // ... and the throttled account can still be used from another address. (The failed-attempt counter of the
        // account is a separate control; it is cleared here so that only the rate limit is being observed.)
        await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == target.Id)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.AccessFailedCount, 0).SetProperty(x => x.LockoutEnd, (DateTimeOffset?)null)));
        using var elsewhere = Stack.NewBrowser(From(21));
        Assert.Equal("/manage", (await Stack.SignInAsync(elsewhere, target)).Url.AbsolutePath);
    }

    [Fact]
    public async Task Login_PerAddressLimit_StopsSprayingAcrossAccounts_ForThatAddressOnly()
    {
        using var browser = Stack.NewBrowser(From(12));
        var login = await browser.GetAsync($"{Stack.IamOrigin}/account/login");

        var spraying = await UntilThrottledAsync(
            RateLimitFixture.Address,
            number => PostLoginAsync(browser, login, $"spray-{number}-{Guid.NewGuid():N}@example.test", "wrong-guess"),
            IsPlainRejection);

        AssertRetryAfter(spraying.Throttled.Header("Retry-After"));
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync($"{Stack.IamOrigin}/account/login")).Status);

        using var elsewhere = Stack.NewBrowser(From(22));
        var elsewhereLogin = await elsewhere.GetAsync($"{Stack.IamOrigin}/account/login");
        var allowed = await PostLoginAsync(elsewhere, elsewhereLogin, $"nobody-{Guid.NewGuid():N}@example.test", "wrong-guess");
        Assert.Equal(HttpStatusCode.OK, allowed.Status);
    }

    [Fact]
    public async Task Recovery_Limit_CoversForgotAndResetPosts_ForOneAddress()
    {
        using var browser = Stack.NewBrowser(From(14));
        var form = await browser.GetAsync($"{Stack.IamOrigin}/account/forgot-password");

        var requests = await UntilThrottledAsync(
            RateLimitFixture.Recovery,
            number => browser.SubmitAsync(form, "form[action*='/account/forgot-password']", new Dictionary<string, string> { ["Email"] = $"nobody-{number}-{Guid.NewGuid():N}@example.test" }),
            IsPlainRejection);

        AssertRetryAfter(requests.Throttled.Header("Retry-After"));
        var reset = await browser.PostFormAsync($"{Stack.IamOrigin}/account/reset-password", [new("Token", "anything"), new("NewPassword", ResetFlow.NewPassword())]);
        Assert.True(IsPlainRejection(reset));
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync($"{Stack.IamOrigin}/account/forgot-password")).Status);

        using var elsewhere = Stack.NewBrowser(From(24));
        var elsewhereForm = await elsewhere.GetAsync($"{Stack.IamOrigin}/account/forgot-password");
        var allowed = await elsewhere.SubmitAsync(elsewhereForm, "form[action*='/account/forgot-password']", new Dictionary<string, string> { ["Email"] = $"nobody-{Guid.NewGuid():N}@example.test" });
        Assert.Equal(HttpStatusCode.OK, allowed.Status);
    }

    [Fact]
    public async Task Signup_Limit_StopsMassRegistration_AndCreatesNoAccountOnceReached()
    {
        using var browser = Stack.NewBrowser(From(15));
        var form = await browser.GetAsync($"{Stack.IamOrigin}/account/register");
        Task<Page> RegisterAsync(string email) => browser.SubmitAsync(form, "form[action*='/account/register']", new Dictionary<string, string>
        {
            ["Input.DisplayName"] = "Mass Signup",
            ["Input.Email"] = email,
            ["Input.Password"] = ResetFlow.NewPassword(),
        });

        var emails = new List<string>();
        var registrations = await UntilThrottledAsync(
            RateLimitFixture.Signup,
            _ =>
            {
                emails.Add($"mass-{Guid.NewGuid():N}@example.test");
                return RegisterAsync(emails[^1]);
            },
            IsPlainRejection);

        AssertRetryAfter(registrations.Throttled.Header("Retry-After"));
        var created = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => emails.Contains(x.Email!)).Select(x => x.Email!).ToListAsync());
        Assert.Equal(emails.Take(registrations.Allowed).Order(), created.Order());
    }

    [Fact]
    public async Task Token_Limit_IsPerClient_AndAnswersWith429AndRetryAfter()
    {
        using var machine = new ProtocolClient(Stack, DemoCatalog.OpsMachineClientId, Stack.Demo.OpsMachineSecret, string.Empty);
        using var pano = ProtocolClient.Pano(Stack);

        var issued = new List<ProtocolResponse>();
        var requests = await UntilThrottledAsync(
            RateLimitFixture.Token,
            async _ =>
            {
                var response = await machine.ClientCredentialsAsync("workspace.jobs");
                issued.Add(response);
                return response;
            },
            response => response.Status == HttpStatusCode.TooManyRequests);

        Assert.All(issued.Take(requests.Allowed), response => Assert.Equal(HttpStatusCode.OK, response.Status));
        AssertRetryAfter(requests.Throttled.Raw.Headers.RetryAfter?.ToString());
        Assert.False(requests.Throttled.Has("access_token"));

        // Another client behind the same address has its own budget: its request is processed (and judged on merit).
        var other = await pano.ExchangeCodeAsync("not-a-real-code", "not-a-real-verifier");
        Assert.Equal(HttpStatusCode.BadRequest, other.Status);
        Assert.Equal("invalid_grant", other.Error);
    }

    [Fact]
    public async Task SecondFactor_Limit_StopsCodeGuessing_AndAlsoCoversRecoveryCodes()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser(From(16));
        var codePage = await MfaFlow.PasswordStepAsync(Stack, browser, account.User);
        Assert.Equal("/account/mfa", codePage.Url.AbsolutePath);
        Task<Page> PostCodeAsync(string code) => browser.SubmitAsync(codePage, "form[action*='/account/mfa']", new Dictionary<string, string> { ["Code"] = code }, follow: false);

        var guessing = await UntilThrottledAsync(RateLimitFixture.Mfa, _ => PostCodeAsync("000000"), IsPlainRejection);

        AssertRetryAfter(guessing.Throttled.Header("Retry-After"));

        // Once throttled, even the right code and the recovery-code form are refused before they are evaluated.
        Assert.True(IsPlainRejection(await PostCodeAsync(account.Device.NextCode())));
        var recovery = await browser.PostFormAsync($"{Stack.IamOrigin}/account/recovery", [new("Code", account.RecoveryCodes[0])], follow: false);
        Assert.True(IsPlainRejection(recovery));
        Assert.Null(browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));
        var unused = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().RecoveryCodes.CountAsync(x => x.UserId == account.User.Id && x.UsedAt == null));
        Assert.Equal(account.RecoveryCodes.Count, unused);
    }
}
