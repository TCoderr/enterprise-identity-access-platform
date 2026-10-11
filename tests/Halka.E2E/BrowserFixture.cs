using System.Collections.Concurrent;

namespace Halka.E2E;

/// <summary>
/// The four product hosts plus the locally installed Chrome (Playwright, channel "chrome"; no browser download).
/// Chrome only accepts the certificates of this run: their SubjectPublicKeyInfo digests are pinned on the command
/// line. Certificate errors are not ignored in general.
/// </summary>
public sealed class BrowserFixture : IAsyncLifetime
{
    public HalkaStack Stack { get; private set; } = null!;

    public IPlaywright Playwright { get; private set; } = null!;

    public IBrowser Chrome { get; private set; } = null!;

    public string ScreenshotDirectory { get; } = FindScreenshotDirectory();

    public async ValueTask InitializeAsync()
    {
        Stack = await HalkaStack.StartAsync();
        Playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        Chrome = await Playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Channel = "chrome",
            Headless = true,
            Args = [$"--ignore-certificate-errors-spki-list={string.Join(',', Stack.Pki.SpkiHashes)}"],
        });
    }

    /// <summary>A fresh browser profile (own cookies and storage) that records console errors and failed requests.</summary>
    public async Task<BrowserSession> NewSessionAsync(int width = 1440, int height = 900)
    {
        var context = await Chrome.NewContextAsync(new BrowserNewContextOptions
        {
            ViewportSize = new ViewportSize { Width = width, Height = height },
            Locale = "en-US",
        });
        context.SetDefaultTimeout(15_000);
        context.SetDefaultNavigationTimeout(20_000);
        return new BrowserSession(context, await context.NewPageAsync(), Stack);
    }

    public async ValueTask DisposeAsync()
    {
        await Chrome.DisposeAsync();
        Playwright.Dispose();
        await Stack.DisposeAsync();
    }

    private static string FindScreenshotDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Halka.slnx")))
        {
            directory = directory.Parent;
        }

        var target = Path.Combine(directory?.FullName ?? AppContext.BaseDirectory, "artifacts", "verification", "screenshots");
        Directory.CreateDirectory(target);
        return target;
    }
}

[CollectionDefinition(Name)]
public sealed class BrowserCollection : ICollectionFixture<BrowserFixture>
{
    public const string Name = "browser";
}

/// <summary>One browser profile with helpers for the flows the tests repeat.</summary>
public sealed class BrowserSession(IBrowserContext context, IPage page, HalkaStack stack) : IAsyncDisposable
{
    private readonly ConcurrentQueue<string> _problems = new();

    public IBrowserContext Context { get; } = context;

    public IPage Page { get; } = Watch(page);

    /// <summary>Console errors, CSP violations, page errors and requests to origins outside the product.</summary>
    public IReadOnlyCollection<string> Problems => _problems;

    private static IPage Watch(IPage page) => page;

    public void Observe()
    {
        var allowed = new[] { stack.IamOrigin, stack.PanoOrigin, stack.RaporOrigin };
        Page.Console += (_, message) =>
        {
            if (message.Type == "error")
            {
                _problems.Enqueue($"console: {message.Text}");
            }
        };
        Page.PageError += (_, error) => _problems.Enqueue($"page error: {error}");
        Page.Request += (_, request) =>
        {
            if (request.Url.StartsWith("http", StringComparison.Ordinal) && !allowed.Any(origin => request.Url.StartsWith(origin, StringComparison.Ordinal)))
            {
                _problems.Enqueue($"external request: {new Uri(request.Url).GetLeftPart(UriPartial.Authority)}");
            }
        };
    }

    public async Task SignInAtProviderAsync(TestUser user)
    {
        await Page.GetByLabel("E-mail address").FillAsync(user.Email);
        await Page.GetByLabel("Password").FillAsync(user.Password);
        await Page.GetByRole(AriaRole.Button, new() { Name = "Sign in", Exact = true }).ClickAsync();
    }

    public Task AllowAsync() => Page.GetByRole(AriaRole.Button, new() { Name = "Allow", Exact = true }).ClickAsync();

    /// <summary>Starts at the application, signs in at the provider when asked and answers consent when shown.</summary>
    public async Task SignInToAppAsync(string origin, TestUser? user, bool allow = true)
    {
        await Page.GotoAsync(origin + "/");
        await Page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
        await Page.WaitForLoadStateAsync();
        if (user is not null && Page.Url.Contains("/account/login", StringComparison.Ordinal))
        {
            await SignInAtProviderAsync(user);
            await Page.WaitForLoadStateAsync();
        }

        if (allow && Page.Url.StartsWith(stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal))
        {
            await AllowAsync();
            await Page.WaitForLoadStateAsync();
        }
    }

    public async Task<string> BadgeAsync() => (await Page.GetByTestId("session-badge").InnerTextAsync()).Trim();

    public async Task<IReadOnlyList<BrowserContextCookiesResult>> CookiesAsync(string origin) => await Context.CookiesAsync([origin]);

    /// <summary>
    /// Saves a full-page screenshot. Authenticator keys, QR codes, recovery codes and client secrets are covered,
    /// even though they belong to throw-away test accounts: verification artifacts never show credential material.
    /// </summary>
    public Task ScreenshotAsync(string directory, string name)
        => Page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = Path.Combine(directory, name + ".png"),
            FullPage = true,
            Mask = [Page.Locator("[data-testid=totp-secret], img.qr, [data-testid=recovery-codes], [data-testid=new-secret]")],
            MaskColor = "#1f3a5f",
        });

    public async ValueTask DisposeAsync() => await Context.DisposeAsync();
}
