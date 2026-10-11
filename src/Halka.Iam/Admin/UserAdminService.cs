using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mfa;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Halka.Iam.Admin;

public sealed record AdminResult(bool Succeeded, string? Error = null)
{
    public static AdminResult Ok { get; } = new(true);

    public static AdminResult Fail(string error) => new(false, error);
}

/// <summary>
/// Administrative changes to accounts. Every method decides on current database state inside one transaction;
/// identifiers and roles come from the server, never from a form. Changes that could remove the last active
/// PlatformAdmin are serialised with an advisory lock so two concurrent requests cannot both pass the check.
/// </summary>
public sealed class UserAdminService(
    IamDbContext db,
    UserManager<ApplicationUser> users,
    RevocationService revocation,
    MfaService mfa,
    AuditWriter audit,
    TimeProvider time)
{
    private const long AdministratorLock = 0x48414C4B_41444D4E; // "HALKADMN"

    /// <summary>Disables or re-enables an account. Disabling ends every session and revokes every grant at once.</summary>
    public async Task<AdminResult> SetDisabledAsync(Guid userId, bool disabled, Guid actorId, CancellationToken cancellationToken)
    {
        if (disabled && userId == actorId)
        {
            return AdminResult.Fail("You cannot disable your own account.");
        }

        var now = time.GetUtcNow();
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        await LockAdministratorsAsync(cancellationToken);
        var user = await db.Users.AsNoTracking().Where(x => x.Id == userId).Select(x => new { x.Id, x.IsDisabled }).SingleOrDefaultAsync(cancellationToken);
        if (user is null)
        {
            return AdminResult.Fail("The account does not exist.");
        }

        if (disabled && await IsLastActivePlatformAdminAsync(userId, cancellationToken))
        {
            audit.Add("user.disable", AuditOutcome.Denied, AuditActor.User, actorId.ToString(), "user", userId.ToString(), "last_platform_admin");
            await db.SaveChangesAsync(cancellationToken);
            await scope.CommitAsync(cancellationToken);
            return AdminResult.Fail("This is the last active PlatformAdmin. Assign another one first.");
        }

        if (user.IsDisabled != disabled)
        {
            await db.Users.Where(x => x.Id == userId).ExecuteUpdateAsync(set => set
                .SetProperty(x => x.IsDisabled, disabled)
                .SetProperty(x => x.DisabledAt, disabled ? now : (DateTimeOffset?)null), cancellationToken);
            if (disabled)
            {
                await revocation.EndAllSessionsAsync(userId, SessionEndReason.UserDisabled, AuditActor.User, actorId.ToString(), null, cancellationToken);
            }

            audit.Add(disabled ? "user.disabled" : "user.enabled", AuditOutcome.Success, AuditActor.User, actorId.ToString(), "user", userId.ToString());
            await db.SaveChangesAsync(cancellationToken);
        }

        await scope.CommitAsync(cancellationToken);
        return AdminResult.Ok;
    }

    /// <summary>Clears a lockout caused by failed sign-in attempts.</summary>
    public async Task<AdminResult> UnlockAsync(Guid userId, Guid actorId, CancellationToken cancellationToken)
    {
        var updated = await db.Users.Where(x => x.Id == userId).ExecuteUpdateAsync(set => set
            .SetProperty(x => x.LockoutEnd, (DateTimeOffset?)null)
            .SetProperty(x => x.AccessFailedCount, 0), cancellationToken);
        if (updated == 0)
        {
            return AdminResult.Fail("The account does not exist.");
        }

        await audit.WriteAsync("user.unlocked", AuditOutcome.Success, AuditActor.User, actorId.ToString(), "user", userId.ToString(), cancellationToken: cancellationToken);
        return AdminResult.Ok;
    }

    /// <summary>
    /// Grants or removes an administrative role. Takes effect on the target's next request because roles are read
    /// from the database for every request. The "User" role is fixed and the last active PlatformAdmin is protected.
    /// </summary>
    public async Task<AdminResult> SetRoleAsync(Guid userId, string role, bool granted, Guid actorId, CancellationToken cancellationToken)
    {
        if (!Roles.Administrative.Contains(role, StringComparer.Ordinal))
        {
            return AdminResult.Fail("Only administrative roles can be changed.");
        }

        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        await LockAdministratorsAsync(cancellationToken);
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return AdminResult.Fail("The account does not exist.");
        }

        var has = await users.IsInRoleAsync(user, role);
        if (has == granted)
        {
            await scope.CommitAsync(cancellationToken);
            return AdminResult.Ok;
        }

        if (!granted && role == Roles.PlatformAdmin && !user.IsDisabled && await IsLastActivePlatformAdminAsync(userId, cancellationToken))
        {
            audit.Add("user.role_removed", AuditOutcome.Denied, AuditActor.User, actorId.ToString(), "user", userId.ToString(), "last_platform_admin");
            await db.SaveChangesAsync(cancellationToken);
            await scope.CommitAsync(cancellationToken);
            return AdminResult.Fail("This is the last active PlatformAdmin. Assign another one first.");
        }

        var result = granted ? await users.AddToRoleAsync(user, role) : await users.RemoveFromRoleAsync(user, role);
        if (!result.Succeeded)
        {
            return AdminResult.Fail("The role could not be changed.");
        }

        audit.Add(granted ? "user.role_granted" : "user.role_removed", AuditOutcome.Success, AuditActor.User, actorId.ToString(), "user", userId.ToString(), role);
        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return AdminResult.Ok;
    }

    /// <summary>
    /// Administrator-assisted authenticator reset for a user who lost the device and the recovery codes. It is not a
    /// silent bypass: it is audited with the acting administrator, ends every session of the user, and the user
    /// has to sign in with the password again (administrators must re-enrol before reaching the admin area).
    /// </summary>
    public async Task<AdminResult> ResetMfaAsync(Guid userId, Guid actorId, CancellationToken cancellationToken)
    {
        if (userId == actorId)
        {
            return AdminResult.Fail("Use your own account settings to change your authenticator.");
        }

        var removed = await mfa.RemoveAsync(userId, keepSessionId: null, AuditActor.User, actorId.ToString(), "admin_reset", cancellationToken);
        return removed ? AdminResult.Ok : AdminResult.Fail("The account has no authenticator.");
    }

    private Task LockAdministratorsAsync(CancellationToken cancellationToken)
        => db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({AdministratorLock})", cancellationToken);

    private async Task<bool> IsLastActivePlatformAdminAsync(Guid userId, CancellationToken cancellationToken)
    {
        var active = await (
            from userRole in db.UserRoles
            join role in db.Roles on userRole.RoleId equals role.Id
            join user in db.Users on userRole.UserId equals user.Id
            where role.Name == Roles.PlatformAdmin && !user.IsDisabled
            select user.Id).ToListAsync(cancellationToken);
        return active.Contains(userId) && active.Count == 1;
    }
}
