using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Mail;
using Halka.Iam.Revocation;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Identity;

public sealed record RegistrationResult(bool Accepted, IReadOnlyList<string> Errors)
{
    public static RegistrationResult Ok { get; } = new(true, []);

    public static RegistrationResult Invalid(IEnumerable<string> errors) => new(false, errors.ToList());
}

public sealed record PasswordResetResult(bool Succeeded, bool TokenInvalid, IReadOnlyList<string> Errors)
{
    public static PasswordResetResult Ok { get; } = new(true, false, []);

    public static PasswordResetResult InvalidToken { get; } = new(false, true, []);
}

/// <summary>Self-service account lifecycle: public sign-up, e-mail confirmation and password reset.</summary>
public sealed class AccountService(
    IamDbContext db,
    UserManager<ApplicationUser> users,
    IPasswordHasher<ApplicationUser> hasher,
    OneTimeTokenService tokens,
    MailOutbox outbox,
    AuditWriter audit,
    TimeProvider time,
    IOptions<IamOptions> options)
{
    /// <summary>
    /// Registers a local account with the "User" role only. The outcome does not reveal whether the address already
    /// had an account: both cases are "accepted". The user row, its role, the confirmation token and the outbox
    /// message are committed in one transaction.
    /// </summary>
    public async Task<RegistrationResult> RegisterAsync(string email, string displayName, string password, CancellationToken cancellationToken)
    {
        email = email.Trim();
        displayName = displayName.Trim();
        var candidate = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            DisplayName = displayName,
            CreatedAt = time.GetUtcNow(),
            LockoutEnabled = true,
        };

        var passwordErrors = new List<string>();
        foreach (var validator in users.PasswordValidators)
        {
            var validation = await validator.ValidateAsync(users, candidate, password);
            passwordErrors.AddRange(validation.Errors.Select(error => error.Description));
        }

        if (passwordErrors.Count > 0)
        {
            return RegistrationResult.Invalid(passwordErrors);
        }

        if (await users.FindByEmailAsync(email) is { } existing)
        {
            hasher.HashPassword(candidate, password);
            await audit.WriteAsync("account.register", AuditOutcome.Denied, AuditActor.Anonymous, null, "user", existing.Id.ToString(), "already_registered", cancellationToken);
            return RegistrationResult.Ok;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var created = await users.CreateAsync(candidate, password);
        if (!created.Succeeded)
        {
            return RegistrationResult.Invalid(created.Errors
                .Where(error => error.Code is not ("DuplicateUserName" or "DuplicateEmail"))
                .Select(error => error.Description)
                .DefaultIfEmpty("The account could not be created with these details."));
        }

        var roleResult = await users.AddToRoleAsync(candidate, Roles.User);
        if (!roleResult.Succeeded)
        {
            throw new InvalidOperationException("The default role is missing; run the migrator seed step.");
        }

        var token = tokens.Create(candidate.Id, OneTimeTokenPurpose.ConfirmEmail, options.Value.EmailConfirmationLifetime);
        outbox.Enqueue(new MailPayload(
            MailKind.ConfirmEmail,
            candidate.Id,
            email,
            "Confirm your Halka ID e-mail address",
            options.Value.Link($"/account/confirm-email?token={Uri.EscapeDataString(token)}")));
        audit.Add("account.registered", AuditOutcome.Success, AuditActor.User, candidate.Id.ToString(), "user", candidate.Id.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return RegistrationResult.Ok;
    }

    /// <summary>
    /// Starts a password reset. Nothing in the result tells the caller whether the account exists; a message is
    /// only queued for confirmed, enabled accounts.
    /// </summary>
    public async Task RequestPasswordResetAsync(string email, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(email.Trim());
        if (user is null || user.IsDisabled || !user.EmailConfirmed)
        {
            await audit.WriteAsync("account.password_reset_requested", AuditOutcome.Denied, AuditActor.Anonymous, null, "user", user?.Id.ToString(), "not_eligible", cancellationToken);
            return;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await tokens.InvalidateAsync(user.Id, OneTimeTokenPurpose.ResetPassword, cancellationToken);
        var token = tokens.Create(user.Id, OneTimeTokenPurpose.ResetPassword, options.Value.PasswordResetLifetime);
        outbox.Enqueue(new MailPayload(
            MailKind.ResetPassword,
            user.Id,
            user.Email!,
            "Reset your Halka ID password",
            options.Value.Link($"/account/reset-password?token={Uri.EscapeDataString(token)}")));
        audit.Add("account.password_reset_requested", AuditOutcome.Success, AuditActor.User, user.Id.ToString(), "user", user.Id.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Completes a password reset. The token is single-use (conditional UPDATE), so of several concurrent attempts
    /// with the same token exactly one can succeed. On success every central session and grant of the user is
    /// revoked in the same transaction; an enrolled second factor is kept.
    /// </summary>
    public async Task<PasswordResetResult> ResetPasswordAsync(string? token, string newPassword, RevocationService revocation, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var userId = await tokens.ConsumeAsync(token, OneTimeTokenPurpose.ResetPassword, cancellationToken);
        var user = userId is null ? null : await users.FindByIdAsync(userId.Value.ToString());
        if (user is null || user.IsDisabled)
        {
            await transaction.RollbackAsync(cancellationToken);
            return PasswordResetResult.InvalidToken;
        }

        var errors = new List<string>();
        foreach (var validator in users.PasswordValidators)
        {
            var validation = await validator.ValidateAsync(users, user, newPassword);
            errors.AddRange(validation.Errors.Select(error => error.Description));
        }

        if (errors.Count > 0)
        {
            // Rolling back also releases the token, so the user can correct the password and retry with the same link.
            await transaction.RollbackAsync(cancellationToken);
            return new PasswordResetResult(false, false, errors);
        }

        user.PasswordHash = hasher.HashPassword(user, newPassword);
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.AccessFailedCount = 0;
        user.LockoutEnd = null;
        var updated = await users.UpdateAsync(user);
        if (!updated.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return PasswordResetResult.InvalidToken;
        }

        await revocation.EndAllSessionsAsync(user.Id, Sessions.SessionEndReason.PasswordReset, AuditActor.User, user.Id.ToString(), null, cancellationToken);
        audit.Add("account.password_reset", AuditOutcome.Success, AuditActor.User, user.Id.ToString(), "user", user.Id.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return PasswordResetResult.Ok;
    }

    /// <summary>
    /// Changes the password of a signed-in user. The current password is required. Every other session of the user
    /// (and the grants issued from them) is ended in the same transaction; the session that made the change stays.
    /// </summary>
    public async Task<PasswordResetResult> ChangePasswordAsync(Guid userId, Guid currentSessionId, string currentPassword, string newPassword, RevocationService revocation, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var user = await users.FindByIdAsync(userId.ToString());
        if (user is null || user.IsDisabled)
        {
            return PasswordResetResult.InvalidToken;
        }

        if (await users.IsLockedOutAsync(user) || !await users.CheckPasswordAsync(user, currentPassword))
        {
            await users.AccessFailedAsync(user);
            audit.Add("account.password_change", AuditOutcome.Failure, AuditActor.User, userId.ToString(), "user", userId.ToString(), "wrong_current_password");
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new PasswordResetResult(false, false, ["The current password is not correct."]);
        }

        var errors = new List<string>();
        foreach (var validator in users.PasswordValidators)
        {
            var validation = await validator.ValidateAsync(users, user, newPassword);
            errors.AddRange(validation.Errors.Select(error => error.Description));
        }

        if (currentPassword == newPassword)
        {
            errors.Add("The new password must be different from the current one.");
        }

        if (errors.Count > 0)
        {
            return new PasswordResetResult(false, false, errors);
        }

        user.PasswordHash = hasher.HashPassword(user, newPassword);
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.AccessFailedCount = 0;
        if (!(await users.UpdateAsync(user)).Succeeded)
        {
            return new PasswordResetResult(false, false, ["The password could not be changed. Try again."]);
        }

        await tokens.InvalidateAsync(userId, OneTimeTokenPurpose.ResetPassword, cancellationToken);
        await revocation.EndAllSessionsAsync(userId, Sessions.SessionEndReason.PasswordChanged, AuditActor.User, userId.ToString(), currentSessionId, cancellationToken);
        await db.UserSessions.Where(x => x.Id == currentSessionId)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.PasswordVerifiedAt, time.GetUtcNow()), cancellationToken);
        audit.Add("account.password_changed", AuditOutcome.Success, AuditActor.User, userId.ToString(), "user", userId.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return PasswordResetResult.Ok;
    }

    /// <summary>Consumes a confirmation token (single use) and marks the address as confirmed.</summary>
    public async Task<bool> ConfirmEmailAsync(string? token, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var userId = await tokens.ConsumeAsync(token, OneTimeTokenPurpose.ConfirmEmail, cancellationToken);
        if (userId is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        await db.Users.Where(x => x.Id == userId).ExecuteUpdateAsync(set => set.SetProperty(x => x.EmailConfirmed, true), cancellationToken);
        audit.Add("account.email_confirmed", AuditOutcome.Success, AuditActor.User, userId.ToString(), "user", userId.ToString());
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}
