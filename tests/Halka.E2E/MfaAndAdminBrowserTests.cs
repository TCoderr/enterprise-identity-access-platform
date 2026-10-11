using Halka.Iam.Data;
using Halka.Iam.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;

namespace Halka.E2E;

[Collection(BrowserCollection.Name)]
public sealed class MfaAndAdminBrowserTests(BrowserFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    /// <summary>Makes the session's second factor older than the step-up window without moving the clock.</summary>
    private Task AgeStepUpAsync(Guid userId)
        => Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions
            .Where(x => x.UserId == userId && x.RevokedAt == null)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.MfaVerifiedAt, Stack.Time.GetUtcNow().AddMinutes(-10))
                .SetProperty(x => x.PasswordVerifiedAt, Stack.Time.GetUtcNow().AddMinutes(-10))));

    [Fact]
    public async Task Admin_EnrollsMfa_SignsInWithCodeAndRecoveryCode_AndStepsUpForASensitiveAction()
    {
        var admin = await Stack.CreateUserAsync(Roles.SecurityAdmin);
        var target = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        session.Observe();
        var page = session.Page;

        // 1. Password-only administrator is sent to MFA setup instead of the administration area.
        await page.GotoAsync(Stack.IamOrigin + "/account/login?returnUrl=%2Fadmin");
        await session.SignInAtProviderAsync(admin);
        await page.WaitForURLAsync(url => url.Contains("/manage/mfa", StringComparison.Ordinal));
        await Assertions.Expect(page.GetByRole(AriaRole.Alert)).ToContainTextAsync("Administrators must use two-step sign-in");

        // 2. Enrollment: a real QR image is shown; the key is entered into the test authenticator.
        await page.GetByRole(AriaRole.Link, new() { Name = "Set up an authenticator app" }).ClickAsync();
        await page.WaitForURLAsync(Stack.IamOrigin + "/manage/mfa/enroll");
        var qr = page.Locator("img.qr");
        await Assertions.Expect(qr).ToBeVisibleAsync();
        Assert.True(await qr.EvaluateAsync<bool>("image => image.complete && image.naturalWidth > 100"), "the QR code must be a rendered image, not a placeholder");
        var device = new TotpDevice(Stack, Base32Encoding.ToBytes((await page.GetByTestId("totp-secret").InnerTextAsync()).Trim()));
        await page.GetByLabel("Authentication code").FillAsync(device.NextCode());
        await page.GetByRole(AriaRole.Button, new() { Name = "Turn on two-step sign-in" }).ClickAsync();
        var codes = await page.GetByTestId("recovery-codes").Locator("li").AllInnerTextsAsync();
        Assert.Equal(10, codes.Count);

        // Reloading the page does not show the key or the codes again.
        await page.ReloadAsync();
        Assert.Equal(0, await page.GetByTestId("totp-secret").CountAsync());
        Assert.DoesNotContain(codes[0], await page.ContentAsync());

        // 3. Sign out, sign in with password + authenticator code (pasted with a space).
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign out", Exact = true }).ClickAsync();
        await page.WaitForURLAsync(url => url.Contains("/account/login", StringComparison.Ordinal));
        await page.GotoAsync(Stack.IamOrigin + "/account/login?returnUrl=%2Fadmin%2Fusers");
        await session.SignInAtProviderAsync(admin);
        await page.WaitForURLAsync(url => url.Contains("/account/mfa", StringComparison.Ordinal));
        var code = device.NextCode();
        await page.GetByLabel("Authentication code").FillAsync($"{code[..3]} {code[3..]}");
        await page.GetByRole(AriaRole.Button, new() { Name = "Verify" }).ClickAsync();
        await page.WaitForURLAsync(Stack.IamOrigin + "/admin/users");

        // 4. Sensitive action with a stale confirmation: the step-up page asks for the authenticator, not the password.
        await AgeStepUpAsync(admin.Id);
        await page.GotoAsync($"{Stack.IamOrigin}/admin/users/{target.Id}");
        await page.GetByRole(AriaRole.Button, new() { Name = "Disable account" }).ClickAsync();
        await page.WaitForURLAsync(url => url.Contains("/account/step-up", StringComparison.Ordinal));
        Assert.Equal(0, await page.Locator("input[type=password]").CountAsync());
        Assert.False(await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Users.Where(x => x.Id == target.Id).Select(x => x.IsDisabled).SingleAsync()));
        await page.GetByLabel("Authentication code").FillAsync(device.NextCode());
        await page.GetByRole(AriaRole.Button, new() { Name = "Confirm", Exact = true }).ClickAsync();
        await page.WaitForURLAsync($"{Stack.IamOrigin}/admin/users/{target.Id}");
        await page.GetByRole(AriaRole.Button, new() { Name = "Disable account" }).ClickAsync();
        await Assertions.Expect(page.GetByRole(AriaRole.Status)).ToContainTextAsync("was disabled");

        // 5. Sign out and sign in with a recovery code instead of the authenticator.
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign out", Exact = true }).ClickAsync();
        await page.WaitForURLAsync(url => url.Contains("/account/login", StringComparison.Ordinal));
        await session.SignInAtProviderAsync(admin);
        await page.WaitForURLAsync(url => url.Contains("/account/mfa", StringComparison.Ordinal));
        await page.GetByRole(AriaRole.Link, new() { Name = "Use a recovery code instead" }).ClickAsync();
        await page.GetByLabel("Recovery code").FillAsync(codes[0].ToLowerInvariant());
        await page.GetByRole(AriaRole.Button, new() { Name = "Verify" }).ClickAsync();
        await page.WaitForURLAsync(Stack.IamOrigin + "/manage");

        Assert.Empty(session.Problems);
    }

    [Fact]
    public async Task NormalUser_CannotReachAdministration_AndLoggedOutPagesAreNotServedFromCache()
    {
        var user = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        var page = session.Page;
        await page.GotoAsync(Stack.IamOrigin + "/account/login");
        await session.SignInAtProviderAsync(user);
        await page.WaitForURLAsync(Stack.IamOrigin + "/manage");

        var response = await page.GotoAsync(Stack.IamOrigin + "/admin/users");
        Assert.Equal(403, response!.Status);
        await Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Level = 1 })).ToHaveTextAsync("Access denied");

        // Visit a page with personal data, sign out, then use the browser's back button.
        await page.GotoAsync(Stack.IamOrigin + "/manage/sessions");
        await Assertions.Expect(page.GetByText("This browser")).ToBeVisibleAsync();
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign out", Exact = true }).First.ClickAsync();
        await page.WaitForURLAsync(url => url.Contains("/account/login", StringComparison.Ordinal));
        await page.GoBackAsync();
        await page.WaitForLoadStateAsync();

        // The page was not stored: the browser had to ask the server again and was sent to the sign-in form.
        Assert.Contains("/account/login", page.Url);
        Assert.Equal(0, await page.GetByText("This browser").CountAsync());
        Assert.DoesNotContain(user.Email, await page.ContentAsync());
    }

    [Fact]
    public async Task OpenRedirect_AndCrossSiteConsentPost_AreRefusedInARealBrowser()
    {
        var user = await Stack.CreateUserAsync();
        await using var session = await fixture.NewSessionAsync();
        var page = session.Page;

        // returnUrl pointing elsewhere is ignored.
        await page.GotoAsync(Stack.IamOrigin + "/account/login?returnUrl=" + Uri.EscapeDataString("https://example.org/phish"));
        await session.SignInAtProviderAsync(user);
        await page.WaitForURLAsync(Stack.IamOrigin + "/manage");

        // A page on another site (Rapor's origin stands in for the attacker) auto-submits a consent decision
        // to the identity provider. The browser sends the provider's cookies, but there is no anti-forgery token.
        var grantsBefore = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.CountAsync(x => x.UserId == user.Id));
        await page.GotoAsync(Stack.RaporOrigin + "/");
        var status = await page.EvaluateAsync<int>(
            """
            async (target) => {
              const response = await fetch(target, {
                method: 'POST', mode: 'no-cors', credentials: 'include',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'client_id=pano-web&response_type=code&scope=openid&consent_decision=allow'
              }).catch(() => null);
              return response ? response.status : -1;
            }
            """,
            Stack.IamOrigin + "/connect/authorize");
        Assert.True(status is 0 or -1, "a cross-site response must be opaque or blocked");
        Assert.Equal(grantsBefore, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.CountAsync(x => x.UserId == user.Id)));
        Assert.Equal(0, await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Consents.CountAsync(x => x.UserId == user.Id)));
    }
}
