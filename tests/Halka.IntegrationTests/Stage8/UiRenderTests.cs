using System.Net;
using AngleSharp.Dom;
using Halka.Iam.Identity;
using Halka.Migrator;

namespace Halka.IntegrationTests.Stage8;

/// <summary>
/// Structural checks of every rendered page (the "component" level for a server-rendered UI): document outline,
/// labelled form controls, anti-forgery on every state-changing form, no inline script or style, no external
/// resource, sensitive pages not cacheable.
/// </summary>
[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, "Ui")]
public sealed class UiRenderTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private static void AssertWellFormed(Page page, string origin)
    {
        var where = page.Url.AbsolutePath;
        var document = page.Document;
        Assert.True(page.Status == HttpStatusCode.OK, $"{where}: status {(int)page.Status}");
        Assert.Equal("en", document.DocumentElement.GetAttribute("lang"));
        Assert.False(string.IsNullOrWhiteSpace(document.Title), $"{where}: missing title");
        Assert.True(document.QuerySelectorAll("h1").Length == 1, $"{where}: expected exactly one h1");
        Assert.NotNull(document.QuerySelector("main#main"));
        Assert.NotNull(document.QuerySelector("a.skip-link[href='#main']"));
        Assert.NotNull(document.QuerySelector("header"));
        Assert.NotNull(document.QuerySelector("meta[name=viewport]"));

        // Headings do not skip levels.
        var levels = document.QuerySelectorAll("h1, h2, h3, h4").Select(heading => heading.TagName[1] - '0').ToList();
        for (var index = 1; index < levels.Count; index++)
        {
            Assert.True(levels[index] <= levels[index - 1] + 1, $"{where}: heading level jumps from h{levels[index - 1]} to h{levels[index]}");
        }

        // Every visible form control has an accessible name from a label.
        foreach (var control in document.QuerySelectorAll("input, select, textarea"))
        {
            var type = control.GetAttribute("type") ?? "text";
            if (type is "hidden" or "submit" or "button")
            {
                continue;
            }

            var id = control.GetAttribute("id");
            var labelled = (!string.IsNullOrEmpty(id) && document.QuerySelector($"label[for='{id}']") is not null)
                           || control.Closest("label") is not null
                           || !string.IsNullOrEmpty(control.GetAttribute("aria-label"));
            Assert.True(labelled, $"{where}: control '{control.GetAttribute("name")}' has no label");
        }

        // Buttons and links have text; images have alternative text.
        Assert.All(document.QuerySelectorAll("button, a[href]"), element => Assert.False(string.IsNullOrWhiteSpace(element.TextContent), $"{where}: empty button or link"));
        Assert.All(document.QuerySelectorAll("img"), image => Assert.False(string.IsNullOrWhiteSpace(image.GetAttribute("alt")), $"{where}: image without alt text"));

        // Data tables are captioned and their header cells scoped.
        foreach (var table in document.QuerySelectorAll("table"))
        {
            Assert.NotNull(table.QuerySelector("caption"));
            Assert.All(table.QuerySelectorAll("th"), cell => Assert.False(string.IsNullOrEmpty(cell.GetAttribute("scope")), $"{where}: th without scope"));
        }

        // State-changing forms carry an anti-forgery token; nothing is inline; nothing is loaded from elsewhere.
        foreach (var form in document.QuerySelectorAll("form"))
        {
            if (string.Equals(form.GetAttribute("method"), "post", StringComparison.OrdinalIgnoreCase))
            {
                Assert.True(form.QuerySelector("input[name=__RequestVerificationToken]") is not null, $"{where}: POST form without anti-forgery token ({form.GetAttribute("action")})");
            }
        }

        Assert.Empty(document.QuerySelectorAll("script:not([src]), style, [style], [onclick], [onload], [onsubmit]"));
        foreach (var element in document.QuerySelectorAll("script[src], link[href], img[src]"))
        {
            var reference = element.GetAttribute("src") ?? element.GetAttribute("href")!;
            Assert.True(reference.StartsWith('/') && !reference.StartsWith("//", StringComparison.Ordinal) || reference.StartsWith("data:image/", StringComparison.Ordinal),
                $"{where}: external or unexpected resource {reference[..Math.Min(40, reference.Length)]}");
        }

        Assert.Contains("no-store", page.Header("Cache-Control"));
        Assert.Contains("default-src 'self'", page.Header("Content-Security-Policy"));
        Assert.StartsWith(origin, page.Url.GetLeftPart(UriPartial.Authority));
    }

    [Fact]
    public async Task Ui_AnonymousPages_AreWellFormed()
    {
        using var browser = Stack.NewBrowser();
        foreach (var path in new[] { "/", "/account/login", "/account/register", "/account/forgot-password", "/account/reset-password?token=invalid", "/account/confirm-email?token=x" })
        {
            AssertWellFormed(await browser.GetAsync($"{Stack.IamOrigin}{path}"), Stack.IamOrigin);
        }

        foreach (var origin in new[] { Stack.PanoOrigin, Stack.RaporOrigin })
        {
            foreach (var path in new[] { "/", "/signed-out", "/signin-problem?reason=denied" })
            {
                AssertWellFormed(await browser.GetAsync($"{origin}{path}"), origin);
            }
        }

        // Error pages are generic and well formed too.
        var missing = await browser.GetAsync($"{Stack.IamOrigin}/no-such-page");
        Assert.Equal(HttpStatusCode.NotFound, missing.Status);
        Assert.Single(missing.Document.QuerySelectorAll("h1"));
        Assert.DoesNotContain("Exception", missing.Body);
    }

    [Fact]
    public async Task Ui_AccountPages_SecondFactorPages_AndDemoClients_AreWellFormed()
    {
        var account = await MfaFlow.CreateAccountAsync(Stack);
        using var browser = Stack.NewBrowser();

        var codePage = await MfaFlow.PasswordStepAsync(Stack, browser, account.User);
        AssertWellFormed(codePage, Stack.IamOrigin);
        Assert.Equal("one-time-code", codePage.Find("input[name=Code]")!.GetAttribute("autocomplete"));
        Assert.Equal("numeric", codePage.Find("input[name=Code]")!.GetAttribute("inputmode"));
        AssertWellFormed(await browser.GetAsync($"{Stack.IamOrigin}/account/recovery"), Stack.IamOrigin);
        await MfaFlow.SubmitCodeAsync(browser, codePage, account.Device.NextCode());

        foreach (var path in new[] { "/manage", "/manage/password", "/manage/mfa", "/manage/sessions", "/manage/apps", "/manage/activity", "/account/step-up", "/account/logout" })
        {
            AssertWellFormed(await browser.GetAsync($"{Stack.IamOrigin}{path}"), Stack.IamOrigin);
        }

        // Consent screen, then the signed-in pages of both applications.
        var consent = await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user: null, consent: null);
        AssertWellFormed(consent, Stack.IamOrigin);
        await ClientFlow.ContinueAsync(Stack, browser, consent, user: null);
        await ClientFlow.SignInAsync(Stack, browser, Stack.RaporOrigin, user: null);
        foreach (var origin in new[] { Stack.PanoOrigin, Stack.RaporOrigin })
        {
            foreach (var path in new[] { "/", "/workspace", "/session" })
            {
                AssertWellFormed(await browser.GetAsync($"{origin}{path}"), origin);
            }
        }

        AssertWellFormed(await browser.GetAsync($"{Stack.IamOrigin}/manage/apps"), Stack.IamOrigin);

        // Enrollment page of an account without an authenticator.
        var plain = await Stack.CreateUserAsync();
        using var plainBrowser = Stack.NewBrowser();
        await Stack.SignInAsync(plainBrowser, plain);
        AssertWellFormed(await plainBrowser.GetAsync($"{Stack.IamOrigin}/manage/mfa/enroll"), Stack.IamOrigin);
    }

    [Fact]
    public async Task Ui_AdministrationPages_AreWellFormed()
    {
        var admin = await MfaFlow.CreateAccountAsync(Stack, Roles.PlatformAdmin);
        using var browser = Stack.NewBrowser();
        await MfaFlow.SignInAsync(Stack, browser, admin);
        using var userBrowser = Stack.NewBrowser();
        var user = await Stack.CreateUserAsync();
        using var pano = ProtocolClient.Pano(Stack);
        await pano.SignInAsync(userBrowser, user, "openid profile offline_access workspace.read");

        foreach (var path in new[]
                 {
                     "/admin", "/admin/users", $"/admin/users/{user.Id}", "/admin/sessions", "/admin/grants", "/admin/audit", "/admin/clients",
                     "/admin/clients/new", $"/admin/clients/{DemoCatalog.PanoClientId}", "/admin/scopes", "/admin/keys", "/admin/ops",
                 })
        {
            AssertWellFormed(await browser.GetAsync($"{Stack.IamOrigin}{path}"), Stack.IamOrigin);
        }

        // Unknown identifiers give a plain 404, not an error page with details.
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync($"{Stack.IamOrigin}/admin/users/{Guid.NewGuid()}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync($"{Stack.IamOrigin}/admin/clients/no-such-client")).Status);
    }
}
