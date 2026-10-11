using Deque.AxeCore.Commons;
using Deque.AxeCore.Playwright;
using Halka.Iam.Identity;
using Halka.Migrator;

namespace Halka.E2E;

/// <summary>
/// Automated accessibility and layout checks in real Chrome at three widths. These cover what a tool can decide
/// (axe-core rules, focus order, reflow). They do not replace testing with a screen reader, which was not done.
/// </summary>
[Collection(BrowserCollection.Name)]
public sealed class AccessibilityAndLayoutTests(BrowserFixture fixture)
{
    private static readonly (int Width, int Height, string Name)[] Viewports = [(360, 740, "360"), (768, 1024, "768"), (1440, 900, "1440")];
    private static readonly string[] Tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"];

    private HalkaStack Stack => fixture.Stack;

    private async Task CheckAsync(BrowserSession session, string name, string viewport)
    {
        var page = session.Page;
        await page.WaitForLoadStateAsync();
        var result = await page.RunAxe(new AxeRunOptions { RunOnly = new RunOnlyOptions { Type = "tag", Values = [.. Tags] } });
        var violations = result.Violations.Select(violation =>
            $"{violation.Id} ({violation.Impact}): {violation.Help} -> {string.Join(" | ", violation.Nodes.Take(3).Select(node => node.Html.Length > 120 ? node.Html[..120] : node.Html))}").ToList();
        Assert.True(violations.Count == 0, $"{name} @ {viewport}px: {string.Join("; ", violations)}");

        // Reflow: no horizontal scrolling of the page at this width.
        var overflow = await page.EvaluateAsync<int>("() => document.documentElement.scrollWidth - document.documentElement.clientWidth");
        Assert.True(overflow <= 1, $"{name} @ {viewport}px scrolls horizontally by {overflow}px");

        // A visible table caption is as wide as its table, also where the table is laid out as stacked blocks.
        var squeezed = await page.EvaluateAsync<string[]>("""
            () => [...document.querySelectorAll('table.data > caption:not(.visually-hidden)')]
                .filter(caption => caption.getBoundingClientRect().width < caption.parentElement.getBoundingClientRect().width * 0.9)
                .map(caption => caption.textContent.trim())
            """);
        Assert.True(squeezed.Length == 0, $"{name} @ {viewport}px has a squeezed table caption: {string.Join(" | ", squeezed)}");
        await session.ScreenshotAsync(fixture.ScreenshotDirectory, $"{name}-{viewport}");
    }

    [Fact]
    public async Task A11y_KeyScreens_HaveNoAxeViolations_AndReflow_AtThreeWidths()
    {
        var admin = await MfaFlow.CreateAccountAsync(Stack, Roles.PlatformAdmin);
        var enrolling = await Stack.CreateUserAsync();
        var target = await Stack.CreateUserAsync();

        foreach (var (width, height, name) in Viewports)
        {
            // Anonymous screens.
            await using (var anonymous = await fixture.NewSessionAsync(width, height))
            {
                foreach (var (label, path) in new[] { ("iam-login", "/account/login"), ("iam-register", "/account/register"), ("iam-forgot-password", "/account/forgot-password") })
                {
                    await anonymous.Page.GotoAsync(Stack.IamOrigin + path);
                    await CheckAsync(anonymous, label, name);
                }

                await anonymous.Page.GotoAsync(Stack.PanoOrigin + "/");
                await CheckAsync(anonymous, "pano-home-signed-out", name);
                await anonymous.Page.GotoAsync(Stack.RaporOrigin + "/");
                await CheckAsync(anonymous, "rapor-home-signed-out", name);
            }

            // Enrollment screen of an account without an authenticator.
            await using (var setup = await fixture.NewSessionAsync(width, height))
            {
                await setup.Page.GotoAsync(Stack.IamOrigin + "/account/login?returnUrl=%2Fmanage%2Fmfa%2Fenroll");
                await setup.SignInAtProviderAsync(enrolling);
                await setup.Page.WaitForURLAsync(Stack.IamOrigin + "/manage/mfa/enroll");
                await CheckAsync(setup, "iam-mfa-enroll", name);
            }

            // Administrator: code page, consent, account, administration and both applications.
            await using var session = await fixture.NewSessionAsync(width, height);
            var page = session.Page;
            await page.GotoAsync(Stack.IamOrigin + "/account/login");
            await session.SignInAtProviderAsync(admin.User);
            await page.WaitForURLAsync(url => url.Contains("/account/mfa", StringComparison.Ordinal));
            await CheckAsync(session, "iam-mfa-code", name);
            await page.GetByLabel("Authentication code").FillAsync(admin.Device.NextCode());
            await page.GetByRole(AriaRole.Button, new() { Name = "Verify" }).ClickAsync();
            await page.WaitForURLAsync(Stack.IamOrigin + "/manage");

            foreach (var (label, path) in new[]
                     {
                         ("iam-account", "/manage"), ("iam-mfa", "/manage/mfa"), ("iam-sessions", "/manage/sessions"), ("iam-password", "/manage/password"),
                         ("iam-step-up", "/account/step-up"), ("admin-dashboard", "/admin"), ("admin-users", "/admin/users"), ("admin-user-detail", $"/admin/users/{target.Id}"),
                         ("admin-clients", "/admin/clients"), ("admin-client-new", "/admin/clients/new"), ("admin-client-detail", $"/admin/clients/{DemoCatalog.PanoClientId}"),
                         ("admin-scopes", "/admin/scopes"), ("admin-sessions", "/admin/sessions"), ("admin-grants", "/admin/grants"), ("admin-audit", "/admin/audit"),
                         ("admin-keys", "/admin/keys"), ("admin-ops", "/admin/ops"),
                     })
            {
                await page.GotoAsync(Stack.IamOrigin + path);
                await CheckAsync(session, label, name);
            }

            // Consent screen for Rapor (shown at every width because it is declined each time), then Pano signed in.
            await page.GotoAsync(Stack.RaporOrigin + "/");
            await page.GetByRole(AriaRole.Link, new() { Name = "Sign in with Halka ID" }).First.ClickAsync();
            await page.WaitForURLAsync(url => url.StartsWith(Stack.IamOrigin + "/connect/authorize", StringComparison.Ordinal));
            await CheckAsync(session, "iam-consent", name);
            await page.GetByRole(AriaRole.Button, new() { Name = "Deny", Exact = true }).ClickAsync();
            await page.WaitForURLAsync(url => url.StartsWith(Stack.RaporOrigin + "/signin-problem", StringComparison.Ordinal));
            await CheckAsync(session, "rapor-signin-problem", name);

            await session.SignInToAppAsync(Stack.PanoOrigin, user: null);
            await page.WaitForURLAsync(Stack.PanoOrigin + "/workspace");

            // A note first, so that the notes table and its caption are on the screen whatever ran before this test.
            await page.GetByLabel("Note").FillAsync("layout check");
            await page.GetByRole(AriaRole.Button, new() { Name = "Add note" }).ClickAsync();
            await page.GetByRole(AriaRole.Button, new() { Name = "Load notes", Exact = true }).ClickAsync();
            await Assertions.Expect(page.GetByText("Notes returned by the API")).ToBeVisibleAsync();
            await CheckAsync(session, "pano-workspace", name);
            await page.GotoAsync(Stack.PanoOrigin + "/session");
            await CheckAsync(session, "pano-session", name);
            await page.GotoAsync(Stack.IamOrigin + "/manage/apps");
            await CheckAsync(session, "iam-connected-apps", name);
        }
    }

    [Fact]
    public async Task Keyboard_SignIn_OnAPhoneSizedViewport_WorksWithoutAPointer()
    {
        var user = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync(360, 740);
        var page = session.Page;
        await page.GotoAsync(Stack.IamOrigin + "/account/login");

        // The first focus stop is the skip link; activating it moves focus into the main content.
        await page.EvaluateAsync("() => document.activeElement && document.activeElement.blur()");
        await page.Keyboard.PressAsync("Tab");
        Assert.Equal("Skip to content", await page.EvaluateAsync<string>("() => document.activeElement.textContent.trim()"));
        Assert.True(await page.EvaluateAsync<bool>("() => { const r = document.activeElement.getBoundingClientRect(); return r.top >= 0 && r.width > 0; }"), "the focused skip link must be visible");

        // Every focused control shows a focus indicator.
        async Task<string> FocusedAsync() => await page.EvaluateAsync<string>(
            "() => { const e = document.activeElement; const s = getComputedStyle(e); return `${e.tagName}:${e.getAttribute('name') ?? e.textContent.trim()}|${s.outlineStyle}|${parseFloat(s.outlineWidth)}`; }");

        var order = new List<string>();
        for (var index = 0; index < 6; index++)
        {
            await page.Keyboard.PressAsync("Tab");
            var focused = await FocusedAsync();
            var parts = focused.Split('|');
            Assert.True(parts[1] != "none" && double.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture) >= 2, $"no visible focus indicator on {parts[0]}");
            order.Add(parts[0]);
        }

        // Logical order: brand, e-mail, password, submit, then the secondary links.
        Assert.True(order.IndexOf("INPUT:Input.Email") < order.IndexOf("INPUT:Input.Password"));
        Assert.True(order.IndexOf("INPUT:Input.Password") < order.IndexOf("BUTTON:Sign in"));

        // Fill and submit with the keyboard only.
        await page.GetByLabel("E-mail address").FocusAsync();
        await page.Keyboard.TypeAsync(user.Email);
        await page.Keyboard.PressAsync("Tab");
        await page.Keyboard.TypeAsync(user.Password);
        await page.Keyboard.PressAsync("Enter");
        await page.WaitForURLAsync(Stack.IamOrigin + "/manage");

        // Errors are announced: a failed attempt renders an alert that the field refers to.
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign out", Exact = true }).ClickAsync();
        await page.GetByLabel("E-mail address").FillAsync(user.Email);
        await page.GetByLabel("Password").FillAsync("wrong-password-value");
        await page.Keyboard.PressAsync("Enter");
        await Assertions.Expect(page.GetByRole(AriaRole.Alert)).ToBeVisibleAsync();
        Assert.Equal("login-error", await page.GetByLabel("E-mail address").GetAttributeAsync("aria-describedby"));
    }

    [Fact]
    public async Task ReducedMotion_AndDarkScheme_AreRespected()
    {
        await using var context = await fixture.Chrome.NewContextAsync(new BrowserNewContextOptions { ReducedMotion = ReducedMotion.Reduce, ColorScheme = ColorScheme.Dark });
        var page = await context.NewPageAsync();
        await page.GotoAsync(Stack.IamOrigin + "/account/login");

        var transition = await page.EvaluateAsync<string>("() => getComputedStyle(document.querySelector('.button')).transitionDuration");
        Assert.Contains(transition, new[] { "0s", "0.00001s", "1e-05s" });
        var background = await page.EvaluateAsync<string>("() => getComputedStyle(document.body).backgroundColor");
        Assert.Equal("rgb(16, 22, 29)", background);

        var result = await page.RunAxe(new AxeRunOptions { RunOnly = new RunOnlyOptions { Type = "tag", Values = [.. Tags] } });
        Assert.True(result.Violations.Length == 0, string.Join("; ", result.Violations.Select(violation => $"{violation.Id}: {violation.Help}")));
        await page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(fixture.ScreenshotDirectory, "iam-login-dark-1440.png"), FullPage = true });
    }
}
