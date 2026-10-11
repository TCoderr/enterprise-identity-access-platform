using Halka.Iam.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;

namespace Halka.Iam.Protocol;

/// <summary>
/// Extends client authentication with two product rules while leaving secret hashing and comparison to OpenIddict:
/// a disabled client can never authenticate, and a previous secret is accepted until its rotation grace window ends.
/// </summary>
public sealed class HalkaApplicationManager(
    IOpenIddictApplicationCache<OpenIddictEntityFrameworkCoreApplication<Guid>> cache,
    ILogger<OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication<Guid>>> logger,
    IOptionsMonitor<OpenIddictCoreOptions> options,
    IOpenIddictApplicationStore<OpenIddictEntityFrameworkCoreApplication<Guid>> store,
    IamDbContext db,
    TimeProvider time)
    : OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication<Guid>>(cache, logger, options, store)
{
    public override async ValueTask<bool> ValidateClientSecretAsync(
        OpenIddictEntityFrameworkCoreApplication<Guid> application,
        string secret,
        CancellationToken cancellationToken = default)
    {
        var disabled = await db.ClientSettings.AsNoTracking()
            .Where(x => x.ApplicationId == application.Id)
            .Select(x => (bool?)x.IsDisabled)
            .SingleOrDefaultAsync(cancellationToken);
        if (disabled != false)
        {
            // Unknown settings are treated like a disabled client (fail closed).
            return false;
        }

        if (await base.ValidateClientSecretAsync(application, secret, cancellationToken))
        {
            return true;
        }

        var now = time.GetUtcNow();
        var previous = await db.ClientSecrets.AsNoTracking()
            .Where(x => x.ApplicationId == application.Id && x.RevokedAt == null && x.NotAfter > now)
            .Select(x => x.SecretHash)
            .ToListAsync(cancellationToken);
        foreach (var hash in previous)
        {
            if (await ValidateClientSecretAsync(secret, hash, cancellationToken))
            {
                return true;
            }
        }

        return false;
    }
}
