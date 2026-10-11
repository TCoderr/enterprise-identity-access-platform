using System.ComponentModel.DataAnnotations;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Ops;
using Halka.Iam.Protocol;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Halka.Iam.Pages.Manage;

public sealed class PasswordModel(AccountService accounts, RevocationService revocation, AccountAttemptLimiter limiter) : PageModel
{
    [BindProperty, Required(ErrorMessage = "Enter your current password."), StringLength(256)]
    public string CurrentPassword { get; set; } = string.Empty;

    [BindProperty, Required(ErrorMessage = "Enter a new password."), StringLength(256, ErrorMessage = "The password can be at most 256 characters.")]
    public string NewPassword { get; set; } = string.Empty;

    public IReadOnlyList<string> Errors { get; private set; } = [];

    [TempData]
    public string? Notice { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        if (!ModelState.IsValid)
        {
            Errors = ModelState.Values.SelectMany(entry => entry.Errors).Select(error => error.ErrorMessage).Distinct().ToList();
            return Page();
        }

        if (!limiter.TryAcquire("password-change", session.UserId.ToString()))
        {
            Response.StatusCode = StatusCodes.Status429TooManyRequests;
            Errors = ["Too many attempts. Wait a minute and try again."];
            return Page();
        }

        var result = await accounts.ChangePasswordAsync(session.UserId, session.Id, CurrentPassword, NewPassword, revocation, cancellationToken);
        if (!result.Succeeded)
        {
            Errors = result.Errors.Count > 0 ? result.Errors : ["The password could not be changed."];
            return Page();
        }

        Notice = "Your password was changed. Your other sessions and the applications opened from them were signed out.";
        return RedirectToPage();
    }
}

public sealed record ConnectedApp(string ClientId, string Name, IReadOnlyList<string> Scopes, DateTimeOffset GrantedAt, int ActiveGrants);

/// <summary>Applications the user allowed. Only the signed-in user's own decisions are ever read or changed.</summary>
public sealed class AppsModel(IamDbContext db, ConsentService consents) : PageModel
{
    public IReadOnlyList<ConnectedApp> Apps { get; private set; } = [];

    [TempData]
    public string? Notice { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var userId = HttpContext.RequireCurrentSession().UserId;
        var rows = await (
            from consent in db.Consents.AsNoTracking()
            where consent.UserId == userId && consent.RevokedAt == null
            join application in db.Applications.AsNoTracking() on consent.ClientId equals application.ClientId
            orderby consent.GrantedAt
            select new { consent.ClientId, application.DisplayName, consent.Scopes, consent.GrantedAt }).ToListAsync(cancellationToken);
        var grants = await db.SessionGrants.AsNoTracking()
            .Where(x => x.UserId == userId && x.RevokedAt == null)
            .GroupBy(x => x.ClientId)
            .Select(group => new { ClientId = group.Key, Count = group.Count() })
            .ToDictionaryAsync(x => x.ClientId, x => x.Count, cancellationToken);
        Apps = rows.Select(row => new ConnectedApp(
            row.ClientId,
            row.DisplayName ?? row.ClientId,
            row.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            row.GrantedAt,
            grants.GetValueOrDefault(row.ClientId))).ToList();
    }

    public async Task<IActionResult> OnPostRevokeAsync(string clientId, CancellationToken cancellationToken)
    {
        var session = HttpContext.RequireCurrentSession();
        var revoked = await consents.RevokeAsync(session.UserId, clientId, AuditActor.User, session.UserId.ToString(), cancellationToken);
        if (!revoked)
        {
            return NotFound();
        }

        Notice = "Access was withdrawn. The application's tokens stopped working immediately; it will ask for your permission again next time.";
        return RedirectToPage();
    }
}

public sealed record ActivityEntry(DateTimeOffset OccurredAt, string Action, string Outcome, string? Reason);

/// <summary>The user's own security events: only rows where the user is the actor or the target.</summary>
public sealed class ActivityModel(IamDbContext db) : PageModel
{
    public IReadOnlyList<ActivityEntry> Entries { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var id = HttpContext.RequireCurrentSession().UserId.ToString();
        Entries = await db.AuditEvents.AsNoTracking()
            .Where(x => x.ActorId == id || (x.TargetType == "user" && x.TargetId == id))
            .OrderByDescending(x => x.Id)
            .Take(50)
            .Select(x => new ActivityEntry(x.OccurredAt, x.Action, x.Outcome, x.ActorId == id ? x.Reason : null))
            .ToListAsync(cancellationToken);
    }
}
