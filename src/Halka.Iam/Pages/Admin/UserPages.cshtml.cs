using Halka.Iam.Admin;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mfa;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Halka.Iam.Pages.Admin;

public sealed record UserRow(Guid Id, string Email, string DisplayName, bool IsDisabled, bool IsLockedOut, bool MfaEnabled, IReadOnlyList<string> Roles);

[Authorize(Policy = AuthorizationPolicies.SecurityAdmin)]
public sealed class UsersModel(IamDbContext db, TimeProvider time) : PageModel
{
    public const int PageSize = 25;

    [BindProperty(SupportsGet = true)]
    public string? Search { get; set; }

    [BindProperty(SupportsGet = true)]
    public int PageNumber { get; set; } = 1;

    public IReadOnlyList<UserRow> Users { get; private set; } = [];

    public bool HasMore { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Clamp(PageNumber, 1, 10_000);
        var query = db.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(Search))
        {
            var term = Search.Trim().ToUpperInvariant();
            query = query.Where(x => x.NormalizedEmail!.Contains(term) || x.DisplayName.ToUpper().Contains(term));
        }

        var now = time.GetUtcNow();
        var page = await query.OrderBy(x => x.NormalizedEmail).Skip((PageNumber - 1) * PageSize).Take(PageSize + 1)
            .Select(x => new { x.Id, x.Email, x.DisplayName, x.IsDisabled, x.LockoutEnd })
            .ToListAsync(cancellationToken);
        HasMore = page.Count > PageSize;
        var ids = page.Take(PageSize).Select(x => x.Id).ToList();
        var roles = await (
            from userRole in db.UserRoles
            join role in db.Roles on userRole.RoleId equals role.Id
            where ids.Contains(userRole.UserId)
            select new { userRole.UserId, role.Name }).ToListAsync(cancellationToken);
        var mfa = await db.UserMfa.AsNoTracking().Where(x => ids.Contains(x.UserId) && x.Status == MfaStatus.Active).Select(x => x.UserId).ToListAsync(cancellationToken);
        Users = page.Take(PageSize).Select(x => new UserRow(
            x.Id,
            x.Email ?? string.Empty,
            x.DisplayName,
            x.IsDisabled,
            x.LockoutEnd is { } end && end > now,
            mfa.Contains(x.Id),
            roles.Where(role => role.UserId == x.Id).Select(role => role.Name!).Order().ToList())).ToList();
    }
}

public sealed record UserSessionRow(Guid Id, string ClientLabel, DateTimeOffset AuthTime, DateTimeOffset LastSeenAt, string Amr);

public sealed record UserGrantRow(Guid AuthorizationId, string ClientId, string Scopes, DateTimeOffset CreatedAt);

/// <summary>
/// One account. The account identifier comes from the route and every session or grant acted on is checked to
/// belong to it; role changes additionally need the PlatformAdmin role. All mutations need a recent step-up.
/// </summary>
[Authorize(Policy = AuthorizationPolicies.SecurityAdmin)]
public sealed class UserDetailModel(
    IamDbContext db,
    UserAdminService admin,
    RevocationService revocation,
    SessionService sessions,
    TimeProvider time) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public Guid Id { get; set; }

    public UserRow Account { get; private set; } = null!;

    public DateTimeOffset CreatedAt { get; private set; }

    public IReadOnlyList<UserSessionRow> Sessions { get; private set; } = [];

    public IReadOnlyList<UserGrantRow> Grants { get; private set; } = [];

    public bool CanManageRoles => HttpContext.RequireCurrentSession().IsInRole(Roles.PlatformAdmin);

    public IReadOnlyList<string> AssignableRoles => Roles.Administrative;

    [TempData]
    public string? Notice { get; set; }

    [TempData]
    public string? Error { get; set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
        => await LoadAsync(cancellationToken) ? Page() : NotFound();

    [RequireStepUp]
    public Task<IActionResult> OnPostDisableAsync(CancellationToken cancellationToken)
        => ApplyAsync(actor => admin.SetDisabledAsync(Id, true, actor, cancellationToken), "The account was disabled. All of its sessions and application grants were revoked.");

    [RequireStepUp]
    public Task<IActionResult> OnPostEnableAsync(CancellationToken cancellationToken)
        => ApplyAsync(actor => admin.SetDisabledAsync(Id, false, actor, cancellationToken), "The account was enabled. The user has to sign in again.");

    [RequireStepUp]
    public Task<IActionResult> OnPostUnlockAsync(CancellationToken cancellationToken)
        => ApplyAsync(actor => admin.UnlockAsync(Id, actor, cancellationToken), "The lockout was cleared.");

    [RequireStepUp]
    public Task<IActionResult> OnPostResetMfaAsync(CancellationToken cancellationToken)
        => ApplyAsync(actor => admin.ResetMfaAsync(Id, actor, cancellationToken), "The authenticator was removed and the user was signed out everywhere. This reset is recorded in the audit log.");

    [RequireStepUp]
    public async Task<IActionResult> OnPostRoleAsync(string role, bool grant, CancellationToken cancellationToken)
    {
        if (!CanManageRoles)
        {
            return Forbid();
        }

        return await ApplyAsync(actor => admin.SetRoleAsync(Id, role, grant, actor, cancellationToken),
            grant ? $"The role {role} was granted." : $"The role {role} was removed. It no longer applies from the user's next request.");
    }

    [RequireStepUp]
    public async Task<IActionResult> OnPostRevokeSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var actor = HttpContext.RequireCurrentSession();
        var owned = await db.UserSessions.AnyAsync(x => x.Id == sessionId && x.UserId == Id && x.RevokedAt == null, cancellationToken);
        if (!owned)
        {
            return NotFound();
        }

        await revocation.EndSessionAsync(sessionId, SessionEndReason.AdminRevoked, AuditActor.User, actor.UserId.ToString(), cancellationToken);
        Notice = "The session was ended.";
        return RedirectToPage(new { Id });
    }

    [RequireStepUp]
    public async Task<IActionResult> OnPostRevokeGrantAsync(Guid authorizationId, CancellationToken cancellationToken)
    {
        var actor = HttpContext.RequireCurrentSession();
        var owned = await db.SessionGrants.AnyAsync(x => x.AuthorizationId == authorizationId && x.UserId == Id && x.RevokedAt == null, cancellationToken);
        if (!owned)
        {
            return NotFound();
        }

        await revocation.RevokeGrantAsync(authorizationId, RevocationReason.AdminRevoked, AuditActor.User, actor.UserId.ToString(), cancellationToken);
        Notice = "The grant was revoked. Its tokens stopped working immediately.";
        return RedirectToPage(new { Id });
    }

    private async Task<IActionResult> ApplyAsync(Func<Guid, Task<AdminResult>> action, string success)
    {
        if (!await db.Users.AnyAsync(x => x.Id == Id))
        {
            return NotFound();
        }

        var result = await action(HttpContext.RequireCurrentSession().UserId);
        if (result.Succeeded)
        {
            Notice = success;
        }
        else
        {
            Error = result.Error;
        }

        return RedirectToPage(new { Id });
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var user = await db.Users.AsNoTracking().Where(x => x.Id == Id)
            .Select(x => new { x.Id, x.Email, x.DisplayName, x.IsDisabled, x.LockoutEnd, x.CreatedAt })
            .SingleOrDefaultAsync(cancellationToken);
        if (user is null)
        {
            return false;
        }

        var roles = await (
            from userRole in db.UserRoles
            join role in db.Roles on userRole.RoleId equals role.Id
            where userRole.UserId == Id
            select role.Name!).ToListAsync(cancellationToken);
        var mfa = await db.UserMfa.AnyAsync(x => x.UserId == Id && x.Status == MfaStatus.Active, cancellationToken);
        Account = new UserRow(user.Id, user.Email ?? string.Empty, user.DisplayName, user.IsDisabled, user.LockoutEnd is { } end && end > now, mfa, roles.Order().ToList());
        CreatedAt = user.CreatedAt;
        Sessions = await sessions.Active(now).Where(x => x.UserId == Id).OrderByDescending(x => x.LastSeenAt)
            .Select(x => new UserSessionRow(x.Id, x.ClientLabel, x.AuthTime, x.LastSeenAt, x.Amr)).ToListAsync(cancellationToken);
        Grants = await db.SessionGrants.AsNoTracking().Where(x => x.UserId == Id && x.RevokedAt == null).OrderByDescending(x => x.CreatedAt)
            .Select(x => new UserGrantRow(x.AuthorizationId, x.ClientId, x.Scopes, x.CreatedAt)).ToListAsync(cancellationToken);
        return true;
    }
}

public sealed record AdminSessionRow(Guid Id, Guid UserId, string Email, string ClientLabel, DateTimeOffset AuthTime, DateTimeOffset LastSeenAt, string Amr);

[Authorize(Policy = AuthorizationPolicies.SecurityAdmin)]
public sealed class SessionsModel(IamDbContext db, SessionService sessions, RevocationService revocation, TimeProvider time) : PageModel
{
    public IReadOnlyList<AdminSessionRow> Items { get; private set; } = [];

    [TempData]
    public string? Notice { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
        => Items = await (
            from session in sessions.Active(time.GetUtcNow())
            join user in db.Users on session.UserId equals user.Id
            orderby session.LastSeenAt descending
            select new AdminSessionRow(session.Id, user.Id, user.Email!, session.ClientLabel, session.AuthTime, session.LastSeenAt, session.Amr))
            .Take(200).ToListAsync(cancellationToken);

    [RequireStepUp]
    public async Task<IActionResult> OnPostRevokeAsync(Guid id, CancellationToken cancellationToken)
    {
        var ended = await revocation.EndSessionAsync(id, SessionEndReason.AdminRevoked, AuditActor.User, HttpContext.RequireCurrentSession().UserId.ToString(), cancellationToken);
        if (ended == 0)
        {
            return NotFound();
        }

        Notice = "The session was ended. Applications opened from it lose access on their next request.";
        return RedirectToPage();
    }
}

public sealed record AdminGrantRow(Guid AuthorizationId, Guid UserId, string Email, string ClientId, string Scopes, DateTimeOffset CreatedAt);

[Authorize(Policy = AuthorizationPolicies.SecurityAdmin)]
public sealed class GrantsModel(IamDbContext db, RevocationService revocation) : PageModel
{
    public IReadOnlyList<AdminGrantRow> Items { get; private set; } = [];

    [TempData]
    public string? Notice { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
        => Items = await (
            from grant in db.SessionGrants.AsNoTracking()
            join user in db.Users on grant.UserId equals user.Id
            where grant.RevokedAt == null
            orderby grant.CreatedAt descending
            select new AdminGrantRow(grant.AuthorizationId, user.Id, user.Email!, grant.ClientId, grant.Scopes, grant.CreatedAt))
            .Take(200).ToListAsync(cancellationToken);

    [RequireStepUp]
    public async Task<IActionResult> OnPostRevokeAsync(Guid id, CancellationToken cancellationToken)
    {
        var revoked = await revocation.RevokeGrantAsync(id, RevocationReason.AdminRevoked, AuditActor.User, HttpContext.RequireCurrentSession().UserId.ToString(), cancellationToken);
        if (revoked == 0)
        {
            return NotFound();
        }

        Notice = "The grant was revoked. Its tokens stopped working immediately.";
        return RedirectToPage();
    }
}

public sealed record AuditRow(long Id, DateTimeOffset OccurredAt, string ActorType, string? ActorId, string Action, string? TargetType, string? TargetId, string Outcome, string? Reason, string? CorrelationId);

/// <summary>Read-only view of the append-only audit log.</summary>
[Authorize(Policy = AuthorizationPolicies.SecurityAdmin)]
public sealed class AuditModel(IamDbContext db) : PageModel
{
    public const int PageSize = 50;

    [BindProperty(SupportsGet = true)]
    public string? EventPrefix { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Subject { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Outcome { get; set; }

    [BindProperty(SupportsGet = true)]
    public long? Before { get; set; }

    public IReadOnlyList<AuditRow> Items { get; private set; } = [];

    public long? NextBefore { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var query = db.AuditEvents.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(EventPrefix))
        {
            var prefix = EventPrefix.Trim();
            query = query.Where(x => x.Action.StartsWith(prefix));
        }

        if (!string.IsNullOrWhiteSpace(Subject))
        {
            var subject = Subject.Trim();
            query = query.Where(x => x.ActorId == subject || x.TargetId == subject || x.Reason!.Contains(subject));
        }

        if (Outcome is AuditOutcome.Success or AuditOutcome.Failure or AuditOutcome.Denied)
        {
            query = query.Where(x => x.Outcome == Outcome);
        }

        if (Before is { } before)
        {
            query = query.Where(x => x.Id < before);
        }

        var rows = await query.OrderByDescending(x => x.Id).Take(PageSize + 1)
            .Select(x => new AuditRow(x.Id, x.OccurredAt, x.ActorType, x.ActorId, x.Action, x.TargetType, x.TargetId, x.Outcome, x.Reason, x.CorrelationId))
            .ToListAsync(cancellationToken);
        Items = rows.Take(PageSize).ToList();
        NextBefore = rows.Count > PageSize ? Items[^1].Id : null;
    }
}
