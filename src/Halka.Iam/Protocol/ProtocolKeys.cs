using System.Security.Cryptography;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Halka.Iam.Protocol;

public sealed class ProtocolOptions
{
    public const string SectionName = "Protocol";

    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromHours(4);

    /// <summary>Safety margin added to the longest token lifetime before a retiring key may be removed.</summary>
    public TimeSpan KeyRetirementSkew { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan DefaultClientSecretGrace { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan MaximumClientSecretGrace { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Reference tokens are stored signed and encrypted with these keys, so a key must remain available for
    /// validation at least as long as the longest-lived token it protected.
    /// </summary>
    public TimeSpan KeyOverlap => new[] { AuthorizationCodeLifetime, AccessTokenLifetime, IdentityTokenLifetime, RefreshTokenLifetime }.Max() + KeyRetirementSkew;
}

public sealed record LoadedProtocolKey(Guid Id, string Use, string Kid, string Status, RsaSecurityKey Key);

public sealed class KeyLifecycleException(string message) : InvalidOperationException(message);

/// <summary>
/// In-memory view of the usable protocol keys (active and retiring). The OpenIddict server options are rebuilt from
/// it whenever it is reloaded, so rotation takes effect without a restart and survives one (keys live in the database).
/// </summary>
public sealed class ProtocolKeyRing(
    IServiceScopeFactory scopes,
    IDataProtectionProvider protection,
    IOptionsMonitorCache<OpenIddictServerOptions> optionsCache)
{
    public const string ProtectorPurpose = "Halka.Iam.ProtocolKeys.v1";

    private volatile IReadOnlyList<LoadedProtocolKey> _keys = [];

    public IReadOnlyList<LoadedProtocolKey> Keys => _keys;

    public async Task ReloadAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IamDbContext>();
        var rows = await db.ProtocolKeys.AsNoTracking()
            .Where(x => x.Status == ProtocolKeyStatus.Active || x.Status == ProtocolKeyStatus.Retiring)
            .OrderBy(x => x.CreatedAt)
            .ToListAsync(cancellationToken);

        var protector = protection.CreateProtector(ProtectorPurpose);
        var loaded = new List<LoadedProtocolKey>(rows.Count);
        foreach (var row in rows)
        {
            var rsa = RSA.Create();
            var pkcs8 = protector.Unprotect(row.ProtectedPrivateKey);
            try
            {
                rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }

            loaded.Add(new LoadedProtocolKey(row.Id, row.Use, row.Kid, row.Status, new RsaSecurityKey(rsa) { KeyId = row.Kid }));
        }

        _keys = loaded;
        optionsCache.TryRemove(Options.DefaultName);
    }
}

/// <summary>Feeds the key ring into the OpenIddict server options and makes the active key the one that signs.</summary>
public sealed class ProtocolKeyOptionsSetup(ProtocolKeyRing ring)
    : IConfigureOptions<OpenIddictServerOptions>, IPostConfigureOptions<OpenIddictServerOptions>
{
    public void Configure(OpenIddictServerOptions options)
    {
        foreach (var key in ring.Keys)
        {
            if (key.Use == ProtocolKeyUse.Signing)
            {
                options.SigningCredentials.Add(new SigningCredentials(key.Key, SecurityAlgorithms.RsaSha256));
            }
            else
            {
                options.EncryptionCredentials.Add(new EncryptingCredentials(key.Key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
            }
        }
    }

    /// <summary>
    /// OpenIddict signs with the first credential of the list and its own ordering does not distinguish plain RSA
    /// keys, so the active key is moved to the front explicitly. Retiring keys stay for validation only.
    /// </summary>
    public void PostConfigure(string? name, OpenIddictServerOptions options)
    {
        var active = ring.Keys.Where(key => key.Status == ProtocolKeyStatus.Active).Select(key => key.Kid).ToHashSet(StringComparer.Ordinal);
        MoveToFront(options.SigningCredentials, credentials => active.Contains(credentials.Key.KeyId));
        MoveToFront(options.EncryptionCredentials, credentials => active.Contains(credentials.Key.KeyId));
    }

    private static void MoveToFront<T>(List<T> list, Func<T, bool> isActive)
    {
        var first = list.Where(isActive).ToList();
        var rest = list.Where(item => !isActive(item)).ToList();
        list.Clear();
        list.AddRange(first);
        list.AddRange(rest);
    }
}

/// <summary>Key lifecycle: initial creation, rotation with overlap, retirement and emergency revocation.</summary>
public sealed class ProtocolKeyService(
    IamDbContext db,
    ProtocolKeyRing ring,
    IDataProtectionProvider protection,
    RevocationService revocation,
    AuditWriter audit,
    TimeProvider time,
    IOptions<ProtocolOptions> options)
{
    private const long LockKey = 0x48414C4B_4B455953; // "HALKKEYS"

    /// <summary>Creates the first signing and encryption keys when none is active. Returns true when it created any.</summary>
    public async Task<bool> EnsureInitialKeysAsync(CancellationToken cancellationToken)
    {
        await using var scope = await TransactionScope.BeginAsync(db, cancellationToken);
        await LockAsync(cancellationToken);
        var created = false;
        foreach (var use in new[] { ProtocolKeyUse.Signing, ProtocolKeyUse.Encryption })
        {
            if (!await db.ProtocolKeys.AnyAsync(x => x.Use == use && x.Status == ProtocolKeyStatus.Active, cancellationToken))
            {
                var key = NewKey(use);
                db.ProtocolKeys.Add(key);
                audit.Add("key.created", AuditOutcome.Success, AuditActor.System, null, "key", key.Kid, use);
                created = true;
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return created;
    }

    /// <summary>
    /// Activates a new key. The previous active key keeps validating (and, for signing keys, stays in the JWKS)
    /// until every token it protected has expired.
    /// </summary>
    public async Task<ProtocolKey> RotateAsync(string use, string? actorId, CancellationToken cancellationToken)
    {
        if (use is not (ProtocolKeyUse.Signing or ProtocolKeyUse.Encryption))
        {
            throw new KeyLifecycleException("Unknown key use.");
        }

        var now = time.GetUtcNow();
        ProtocolKey created;
        await using (var scope = await TransactionScope.BeginAsync(db, cancellationToken))
        {
            await LockAsync(cancellationToken);
            var retireNotBefore = now + options.Value.KeyOverlap;
            await db.ProtocolKeys
                .Where(x => x.Use == use && x.Status == ProtocolKeyStatus.Active)
                .ExecuteUpdateAsync(set => set
                    .SetProperty(x => x.Status, ProtocolKeyStatus.Retiring)
                    .SetProperty(x => x.RetiringSince, now)
                    .SetProperty(x => x.RetireNotBefore, retireNotBefore), cancellationToken);
            created = NewKey(use);
            db.ProtocolKeys.Add(created);
            audit.Add("key.rotated", AuditOutcome.Success, AuditActor.User, actorId, "key", created.Kid, use);
            await db.SaveChangesAsync(cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        await ring.ReloadAsync(cancellationToken);
        return created;
    }

    /// <summary>Removes a retiring key. Refused while tokens protected by it may still be valid.</summary>
    public async Task RetireAsync(Guid keyId, string? actorId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using (var scope = await TransactionScope.BeginAsync(db, cancellationToken))
        {
            await LockAsync(cancellationToken);
            var key = await db.ProtocolKeys.SingleOrDefaultAsync(x => x.Id == keyId, cancellationToken)
                      ?? throw new KeyLifecycleException("The key does not exist.");
            if (key.Status != ProtocolKeyStatus.Retiring)
            {
                throw new KeyLifecycleException("Only a retiring key can be retired. Rotate first.");
            }

            if (key.RetireNotBefore is { } notBefore && now < notBefore)
            {
                audit.Add("key.retire", AuditOutcome.Denied, AuditActor.User, actorId, "key", key.Kid, "overlap_not_elapsed");
                await db.SaveChangesAsync(cancellationToken);
                await scope.CommitAsync(cancellationToken);
                throw new KeyLifecycleException($"This key still protects tokens that may be valid. It can be retired after {notBefore:yyyy-MM-dd HH:mm} UTC.");
            }

            key.Status = ProtocolKeyStatus.Retired;
            key.RetiredAt = now;
            key.ProtectedPrivateKey = [];
            audit.Add("key.retired", AuditOutcome.Success, AuditActor.User, actorId, "key", key.Kid, key.Use);
            await db.SaveChangesAsync(cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        await ring.ReloadAsync(cancellationToken);
    }

    /// <summary>
    /// Emergency path for a suspected compromise: the key stops being trusted immediately (no overlap), a new key is
    /// activated when the revoked one was active, and every grant and token is revoked because nothing protected by
    /// the key can be trusted any more. Central sessions are kept; applications re-authorise through SSO.
    /// </summary>
    public async Task<int> EmergencyRevokeAsync(Guid keyId, string? actorId, string reason, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        int revokedGrants;
        await using (var scope = await TransactionScope.BeginAsync(db, cancellationToken))
        {
            await LockAsync(cancellationToken);
            var key = await db.ProtocolKeys.SingleOrDefaultAsync(x => x.Id == keyId, cancellationToken)
                      ?? throw new KeyLifecycleException("The key does not exist.");
            if (key.Status is not (ProtocolKeyStatus.Active or ProtocolKeyStatus.Retiring))
            {
                throw new KeyLifecycleException("The key is not in use.");
            }

            var wasActive = key.Status == ProtocolKeyStatus.Active;
            key.Status = ProtocolKeyStatus.Revoked;
            key.RevokedAt = now;
            key.Reason = reason is { Length: > 200 } ? reason[..200] : reason;
            key.ProtectedPrivateKey = [];
            await db.SaveChangesAsync(cancellationToken);

            if (wasActive)
            {
                var replacement = NewKey(key.Use);
                db.ProtocolKeys.Add(replacement);
                audit.Add("key.created", AuditOutcome.Success, AuditActor.User, actorId, "key", replacement.Kid, key.Use);
            }

            audit.Add("key.emergency_revoked", AuditOutcome.Success, AuditActor.User, actorId, "key", key.Kid, key.Use);
            await db.SaveChangesAsync(cancellationToken);
            revokedGrants = await revocation.RevokeEverythingAsync(RevocationReason.KeyCompromise, AuditActor.User, actorId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        await ring.ReloadAsync(cancellationToken);
        return revokedGrants;
    }

    private ProtocolKey NewKey(string use)
    {
        using var rsa = RSA.Create(2048);
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        try
        {
            var now = time.GetUtcNow();
            return new ProtocolKey
            {
                Id = Guid.NewGuid(),
                Use = use,
                Kid = ComputeKeyId(rsa),
                Algorithm = use == ProtocolKeyUse.Signing ? SecurityAlgorithms.RsaSha256 : SecurityAlgorithms.RsaOAEP,
                Status = ProtocolKeyStatus.Active,
                ProtectedPrivateKey = protection.CreateProtector(ProtocolKeyRing.ProtectorPurpose).Protect(pkcs8),
                CreatedAt = now,
                ActivatedAt = now,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    /// <summary>RFC 7638 JWK thumbprint of the public key, used as "kid".</summary>
    internal static string ComputeKeyId(RSA rsa)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false)));
        return Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
    }

    private Task LockAsync(CancellationToken cancellationToken)
        => db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({LockKey})", cancellationToken);
}

/// <summary>Loads the key ring before the server accepts requests.</summary>
public sealed class ProtocolKeyRingInitializer(ProtocolKeyRing ring) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) => ring.ReloadAsync(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
