using Halka.Iam.Audit;
using Halka.Iam.Mfa;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;

namespace Halka.Iam.Pages.Manage;

public sealed class MfaModel(MfaService mfa) : PageModel
{
    public bool Enabled { get; private set; }

    public int RemainingCodes { get; private set; }

    public bool RequiredForAdministration { get; private set; }

    public IReadOnlyList<string> NewCodes { get; private set; } = [];

    [TempData]
    public string? Notice { get; set; }

    public async Task OnGetAsync(string? required, CancellationToken cancellationToken)
    {
        await LoadAsync(cancellationToken);
        RequiredForAdministration = required == "admin" && !Enabled;
    }

    /// <summary>Requires a recent second factor: a merely signed-in (possibly stolen) session cannot mint new codes.</summary>
    [RequireStepUp]
    public async Task<IActionResult> OnPostRegenerateAsync(CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        if (!session.MfaEnabled)
        {
            return RedirectToPage();
        }

        NewCodes = await mfa.RegenerateRecoveryCodesAsync(session.UserId, cancellationToken);
        await LoadAsync(cancellationToken);
        return Page();
    }

    [RequireStepUp]
    public async Task<IActionResult> OnPostRemoveAsync(bool confirm, CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        if (!confirm)
        {
            return RedirectToPage();
        }

        if (await mfa.RemoveAsync(session.UserId, session.Id, AuditActor.User, session.UserId.ToString(), "self_service", cancellationToken))
        {
            Notice = "Two-step sign-in is turned off. Your other sessions were signed out.";
        }

        return RedirectToPage();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        Enabled = await mfa.IsEnabledAsync(session.UserId, cancellationToken);
        RemainingCodes = Enabled ? await mfa.RemainingRecoveryCodesAsync(session.UserId, cancellationToken) : 0;
    }
}

/// <summary>
/// Authenticator enrollment. Starting it needs a recent password confirmation. The secret is shown only here,
/// while the enrollment is pending, and the QR code is rendered on this server as an embedded image: nothing is
/// sent to a third party and nothing is written to browser storage.
/// </summary>
[RequireStepUp]
public sealed class MfaEnrollModel(MfaService mfa) : PageModel
{
    public string Secret { get; private set; } = string.Empty;

    public string QrDataUri { get; private set; } = string.Empty;

    public string? ErrorMessage { get; private set; }

    public IReadOnlyList<string> NewCodes { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        if (session.MfaEnabled)
        {
            return LocalRedirect("/manage/mfa");
        }

        Show(await mfa.GetPendingEnrollmentAsync(session.UserId, session.Email, cancellationToken)
             ?? await mfa.BeginEnrollmentAsync(session.UserId, session.Email, cancellationToken));
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? code, CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        if (session.MfaEnabled)
        {
            return LocalRedirect("/manage/mfa");
        }

        var codes = await mfa.ActivateAsync(session.UserId, code, session.Id, cancellationToken);
        if (codes is not null)
        {
            NewCodes = codes;
            return Page();
        }

        var pending = await mfa.GetPendingEnrollmentAsync(session.UserId, session.Email, cancellationToken);
        if (pending is null)
        {
            return RedirectToPage();
        }

        ErrorMessage = "The code is not valid. Check the time on your device and enter the current code.";
        Show(pending);
        return Page();
    }

    /// <summary>Discards the pending secret and starts over with a new one.</summary>
    public async Task<IActionResult> OnPostRestartAsync(CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        if (!session.MfaEnabled)
        {
            await mfa.BeginEnrollmentAsync(session.UserId, session.Email, cancellationToken);
        }

        return RedirectToPage();
    }

    private void Show(Enrollment enrollment)
    {
        Secret = enrollment.Base32Secret;
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(enrollment.ProvisioningUri, QRCodeGenerator.ECCLevel.M);
        QrDataUri = "data:image/png;base64," + Convert.ToBase64String(new PngByteQRCode(data).GetGraphic(6));
    }
}
