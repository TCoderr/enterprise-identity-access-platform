using Halka.Iam.Mfa;
using OtpNet;

namespace Halka.TestKit;

/// <summary>
/// A test authenticator "device". The secret comes from the enrollment page of a disposable test account and never
/// leaves the test process. Because the server accepts every time step only once, the device hands out codes of
/// strictly increasing steps: first the previous step, then the current one, then the next (all inside the
/// server's one-step skew window), and only then moves the shared test clock forward.
/// </summary>
public sealed class TotpDevice(HalkaStack stack, byte[] secret)
{
    private long _lastStep = long.MinValue;

    public byte[] Secret { get; } = secret;

    public string Base32 => Base32Encoding.ToString(Secret);

    public long LastStep => _lastStep;

    public string NextCode()
    {
        var current = stack.IamTime.GetUtcNow().ToUnixTimeSeconds() / TotpCodes.StepSeconds;
        var step = Math.Max(_lastStep + 1, current - 1);
        if (step > current + 1)
        {
            stack.Time.Advance(TimeSpan.FromSeconds(TotpCodes.StepSeconds * (step - current - 1)));
            if (!ReferenceEquals(stack.Time, stack.IamTime))
            {
                stack.IamTime.Advance(TimeSpan.FromSeconds(TotpCodes.StepSeconds * (step - current - 1)));
            }
        }

        _lastStep = step;
        return CodeForStep(step);
    }

    /// <summary>The code of the step that was handed out last (for replay tests).</summary>
    public string LastCode() => CodeForStep(_lastStep);

    public string CodeForStep(long step) => TotpCodes.Compute(Secret, DateTimeOffset.FromUnixTimeSeconds(step * TotpCodes.StepSeconds));

    public long CurrentStep => stack.IamTime.GetUtcNow().ToUnixTimeSeconds() / TotpCodes.StepSeconds;
}

public sealed record MfaAccount(TestUser User, TotpDevice Device, IReadOnlyList<string> RecoveryCodes);

/// <summary>Second-factor flows through the real pages.</summary>
public static class MfaFlow
{
    /// <summary>Enrolls an authenticator for the user signed in to <paramref name="browser"/> through the enrollment page.</summary>
    public static async Task<(TotpDevice Device, IReadOnlyList<string> RecoveryCodes)> EnrollAsync(HalkaStack stack, Browser browser)
    {
        var page = await browser.GetAsync($"{stack.IamOrigin}/manage/mfa/enroll");
        var secret = page.Find("[data-testid=totp-secret]")?.TextContent.Trim()
                     ?? throw new InvalidOperationException($"The enrollment page was not shown (landed on {page.Url.AbsolutePath}).");
        var device = new TotpDevice(stack, Base32Encoding.ToBytes(secret));
        var done = await browser.SubmitAsync(page, "form[action='/manage/mfa/enroll']", new Dictionary<string, string> { ["code"] = device.NextCode() });
        var codes = done.Document.QuerySelectorAll("[data-testid=recovery-codes] li").Select(item => item.TextContent.Trim()).ToList();
        if (codes.Count == 0)
        {
            throw new InvalidOperationException("Enrollment was not confirmed: no recovery codes were shown.");
        }

        return (device, codes);
    }

    /// <summary>Creates an account that already has an authenticator (enrolled through the real flow in a throw-away browser).</summary>
    public static async Task<MfaAccount> CreateAccountAsync(HalkaStack stack, params string[] roles)
    {
        var user = await stack.CreateUserAsync(roles);
        using var browser = stack.NewBrowser();
        await stack.SignInAsync(browser, user);
        var (device, codes) = await EnrollAsync(stack, browser);
        var signedOut = await browser.GetAsync($"{stack.IamOrigin}/manage");
        await browser.SubmitAsync(signedOut, "form[action*='/account/logout']");
        return new MfaAccount(user, device, codes);
    }

    /// <summary>Password step; returns the page that follows (the code page for accounts with MFA).</summary>
    public static Task<Page> PasswordStepAsync(HalkaStack stack, Browser browser, TestUser user, string? returnUrl = null)
        => stack.SignInAsync(browser, user, returnUrl);

    public static Task<Page> SubmitCodeAsync(Browser browser, Page codePage, string code)
        => browser.SubmitAsync(codePage, "form[action*='/account/mfa']", new Dictionary<string, string> { ["Code"] = code });

    public static async Task<Page> SubmitRecoveryCodeAsync(HalkaStack stack, Browser browser, Page codePage, string code)
    {
        var recovery = await browser.GetAsync($"{stack.IamOrigin}/account/recovery{codePage.Url.Query}");
        return await browser.SubmitAsync(recovery, "form[action*='/account/recovery']", new Dictionary<string, string> { ["Code"] = code });
    }

    /// <summary>Full sign-in with password and authenticator code.</summary>
    public static async Task<Page> SignInAsync(HalkaStack stack, Browser browser, MfaAccount account, string? returnUrl = null)
    {
        var codePage = await PasswordStepAsync(stack, browser, account.User, returnUrl);
        if (codePage.Url.AbsolutePath != "/account/mfa")
        {
            throw new InvalidOperationException($"Expected the code page after the password, got {codePage.Url.AbsolutePath}.");
        }

        return await SubmitCodeAsync(browser, codePage, account.Device.NextCode());
    }
}
