namespace Halka.TestKit;

/// <summary>Drives a demo relying party (real ASP.NET Core OIDC middleware) the way a user would.</summary>
public static class ClientFlow
{
    public static bool IsLoginPage(Page page) => page.Find("form[action*='/account/login']") is not null;

    public static bool IsConsentPage(Page page) => page.Find("form[action='/connect/authorize']") is not null;

    public static Task<Page> SignInAsync(HalkaStack stack, Browser browser, string clientOrigin, TestUser? user, string? consent = "allow", string path = "/login")
        => SignInAsync(stack.IamOrigin, browser, clientOrigin, user, consent, path);

    /// <summary>
    /// Starts at the client's /login, follows the redirects to the identity provider, signs in there when asked,
    /// answers the consent screen and returns the page the browser finally lands on.
    /// </summary>
    public static async Task<Page> SignInAsync(string identityProviderOrigin, Browser browser, string clientOrigin, TestUser? user, string? consent = "allow", string path = "/login")
    {
        var page = await browser.GetAsync($"{clientOrigin}{path}");
        return await ContinueAsync(identityProviderOrigin, browser, page, user, consent);
    }

    public static Task<Page> ContinueAsync(HalkaStack stack, Browser browser, Page page, TestUser? user, string? consent = "allow")
        => ContinueAsync(stack.IamOrigin, browser, page, user, consent);

    public static async Task<Page> ContinueAsync(string identityProviderOrigin, Browser browser, Page page, TestUser? user, string? consent = "allow")
    {
        var identityProvider = new Uri(identityProviderOrigin).Authority;
        for (var step = 0; step < 6; step++)
        {
            if (page.Url.Authority != identityProvider)
            {
                break;
            }

            if (user is not null && IsLoginPage(page))
            {
                page = await browser.SubmitAsync(page, "form[action*='/account/login']", new Dictionary<string, string>
                {
                    ["Input.Email"] = user.Email,
                    ["Input.Password"] = user.Password,
                });
                user = null;
                continue;
            }

            if (consent is not null && IsConsentPage(page))
            {
                page = await browser.SubmitAsync(page, "form[action='/connect/authorize']", new Dictionary<string, string> { ["consent_decision"] = consent });
                consent = null;
                continue;
            }

            break;
        }

        return page;
    }

    public static string Badge(Page page) => page.Find("[data-testid=session-badge]")?.TextContent.Trim() ?? string.Empty;

    public static string ApiStatus(Page page) => page.Find("[data-testid=api-status]")?.TextContent.Trim() ?? string.Empty;

    public static Task<Page> WorkspaceAsync(Browser browser, Page workspace, string handler, IReadOnlyDictionary<string, string>? fields = null)
        => browser.SubmitAsync(workspace, $"form[action*='handler={handler}']", fields);
}
