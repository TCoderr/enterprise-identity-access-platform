using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Halka.Iam.Data;
using Microsoft.EntityFrameworkCore;

namespace Halka.Iam.Identity;

/// <summary>
/// Issues and consumes single-use account tokens. The raw value is 256 bits from the system CSPRNG and is only handed
/// to the mail outbox; the database stores its SHA-256 hash. Consumption is one conditional UPDATE, so concurrent
/// attempts with the same token produce exactly one success.
/// </summary>
public sealed class OneTimeTokenService(IamDbContext db, TimeProvider time)
{
    public string Create(Guid userId, string purpose, TimeSpan lifetime)
    {
        var raw = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var now = time.GetUtcNow();
        db.OneTimeTokens.Add(new OneTimeToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Purpose = purpose,
            TokenHash = Hash(raw),
            CreatedAt = now,
            ExpiresAt = now + lifetime,
        });
        return raw;
    }

    /// <summary>Returns the owning user id when the token was valid and has now been consumed; otherwise null.</summary>
    public async Task<Guid?> ConsumeAsync(string? rawToken, string purpose, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken) || rawToken.Length > 128)
        {
            return null;
        }

        var hash = Hash(rawToken);
        var now = time.GetUtcNow();
        var candidate = await db.OneTimeTokens.AsNoTracking()
            .Where(x => x.TokenHash == hash && x.Purpose == purpose)
            .Select(x => new { x.Id, x.UserId })
            .SingleOrDefaultAsync(cancellationToken);
        if (candidate is null)
        {
            return null;
        }

        var consumed = await db.OneTimeTokens
            .Where(x => x.Id == candidate.Id && x.ConsumedAt == null && x.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.ConsumedAt, now), cancellationToken);
        return consumed == 1 ? candidate.UserId : null;
    }

    /// <summary>Checks validity without consuming (used to decide whether to render a form).</summary>
    public async Task<bool> IsValidAsync(string? rawToken, string purpose, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken) || rawToken.Length > 128)
        {
            return false;
        }

        var hash = Hash(rawToken);
        var now = time.GetUtcNow();
        return await db.OneTimeTokens.AnyAsync(
            x => x.TokenHash == hash && x.Purpose == purpose && x.ConsumedAt == null && x.ExpiresAt > now,
            cancellationToken);
    }

    /// <summary>Invalidates all outstanding tokens of a purpose for a user (e.g. after a successful reset).</summary>
    public Task<int> InvalidateAsync(Guid userId, string purpose, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        return db.OneTimeTokens
            .Where(x => x.UserId == userId && x.Purpose == purpose && x.ConsumedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(x => x.ConsumedAt, now), cancellationToken);
    }

    internal static byte[] Hash(string rawToken) => SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
}
