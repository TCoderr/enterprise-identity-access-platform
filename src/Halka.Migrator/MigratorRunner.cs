using System.Text.Json;
using Halka.Iam;
using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Protocol;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Halka.Migrator;

public sealed record SeedUser(string Email, string DisplayName, string Role, string Password);

public sealed record SeedData(IReadOnlyList<SeedUser> Users)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static SeedData Empty { get; } = new([]);

    public static SeedData Load(string path)
        => JsonSerializer.Deserialize<SeedData>(File.ReadAllText(path), Json)
           ?? throw new InvalidOperationException($"Seed file could not be read: {path}");
}

/// <summary>
/// Schema and bootstrap operations that need the owner (migration) role. Runtime applications never run these;
/// they connect with a restricted role that cannot change the schema.
/// </summary>
public static class MigratorRunner
{
    /// <summary>Builds the IAM service graph against the migration connection (no HTTP pipeline).</summary>
    public static ServiceProvider BuildIamServices(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddSingleton(configuration);
        services.AddLogging(logging => logging.AddSimpleConsole(options => options.SingleLine = true).SetMinimumLevel(LogLevel.Error));
        IamHost.AddIamCore(services, configuration);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    /// <summary>Applies pending migrations and (re)applies the runtime role grants. Safe to run repeatedly.</summary>
    public static async Task MigrateIamAsync(IServiceProvider services, string runtimeRole, CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IamDbContext>();
        await db.Database.MigrateAsync(cancellationToken);
        foreach (var statement in IamRuntimeGrants(runtimeRole))
        {
#pragma warning disable EF1002 // The role name is validated as a plain identifier by BootstrapSql.Identifier.
            await db.Database.ExecuteSqlRawAsync(statement, cancellationToken);
#pragma warning restore EF1002
        }
    }

    /// <summary>
    /// Least-privilege grants for the runtime role: data access only, no DDL, and the audit table is append-only
    /// (INSERT and SELECT; UPDATE, DELETE and TRUNCATE are revoked).
    /// </summary>
    public static IReadOnlyList<string> IamRuntimeGrants(string runtimeRole)
    {
        var role = BootstrapSql.Identifier(runtimeRole);
        return
        [
            $"GRANT USAGE ON SCHEMA public TO {role}",
            $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}",
            $"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}",
            $"REVOKE ALL ON TABLE \"__EFMigrationsHistory\" FROM {role}",
            $"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE audit_events FROM {role}",
        ];
    }

    /// <summary>
    /// Applies the schema of a demo client database (server-side application sessions) and grants its runtime role
    /// data access to that single table.
    /// </summary>
    public static async Task MigrateClientAsync(string ownerConnectionString, string runtimeRole, CancellationToken cancellationToken)
    {
        var options = new DbContextOptionsBuilder<Halka.DemoClient.ClientDbContext>();
        Halka.DemoClient.ClientDbContext.Configure(options, ownerConnectionString);
        await using var db = new Halka.DemoClient.ClientDbContext(options.Options);
        await db.Database.MigrateAsync(cancellationToken);
        var role = BootstrapSql.Identifier(runtimeRole);
        foreach (var statement in new[]
                 {
                     $"GRANT USAGE ON SCHEMA public TO {role}",
                     $"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app_sessions TO {role}",
                 })
        {
#pragma warning disable EF1002 // The role name is validated as a plain identifier by BootstrapSql.Identifier.
            await db.Database.ExecuteSqlRawAsync(statement, cancellationToken);
#pragma warning restore EF1002
        }
    }

    /// <summary>
    /// Idempotent seed: roles, bootstrap accounts, protocol keys and (when given) the demo scopes and clients.
    /// Existing accounts, keys and client secrets are never modified.
    /// </summary>
    public static async Task SeedIamAsync(IServiceProvider services, SeedData seed, DemoSeed? demo, CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        var provider = scope.ServiceProvider;
        var roles = provider.GetRequiredService<RoleManager<ApplicationRole>>();
        var users = provider.GetRequiredService<UserManager<ApplicationUser>>();
        var time = provider.GetRequiredService<TimeProvider>();

        foreach (var role in Roles.All)
        {
            if (!await roles.RoleExistsAsync(role))
            {
                Ensure(await roles.CreateAsync(new ApplicationRole(role)), $"create role {role}");
            }
        }

        foreach (var entry in seed.Users)
        {
            if (!Roles.All.Contains(entry.Role, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"Seed user has an unknown role: {entry.Role}");
            }

            if (await users.FindByEmailAsync(entry.Email) is not null)
            {
                continue;
            }

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = entry.Email,
                Email = entry.Email,
                EmailConfirmed = true,
                DisplayName = entry.DisplayName,
                CreatedAt = time.GetUtcNow(),
                LockoutEnabled = true,
            };
            Ensure(await users.CreateAsync(user, entry.Password), "create seed user");
            Ensure(await users.AddToRoleAsync(user, Roles.User), "assign default role");
            if (entry.Role != Roles.User)
            {
                Ensure(await users.AddToRoleAsync(user, entry.Role), "assign seed role");
            }
        }

        await provider.GetRequiredService<ProtocolKeyService>().EnsureInitialKeysAsync(cancellationToken);

        if (demo is not null)
        {
            await SeedDemoAsync(provider, demo, cancellationToken);
        }
    }

    private static async Task SeedDemoAsync(IServiceProvider provider, DemoSeed demo, CancellationToken cancellationToken)
    {
        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var registry = provider.GetRequiredService<ClientRegistry>();

        foreach (var scope in DemoCatalog.Scopes)
        {
            if (await scopes.FindByNameAsync(scope.Name, cancellationToken) is not null)
            {
                continue;
            }

            var descriptor = new OpenIddictScopeDescriptor { Name = scope.Name, DisplayName = scope.DisplayName, Description = scope.Description };
            if (scope.Resource is not null)
            {
                descriptor.Resources.Add(scope.Resource);
            }

            await scopes.CreateAsync(descriptor, cancellationToken);
        }

        foreach (var (registration, secret) in DemoCatalog.Clients(demo))
        {
            if (await applications.FindByClientIdAsync(registration.ClientId, cancellationToken) is null)
            {
                await registry.CreateAsync(registration, secret, actorId: null, cancellationToken);
            }
            else
            {
                // Origins can change between runs (ports); redirect URIs and permissions follow the catalog.
                await registry.UpdateAsync(registration, actorId: null, cancellationToken);
            }
        }
    }

    private static void Ensure(IdentityResult result, string operation)
    {
        if (!result.Succeeded)
        {
            // Error codes only: descriptions can echo input values.
            throw new InvalidOperationException($"Could not {operation}: {string.Join(", ", result.Errors.Select(error => error.Code))}");
        }
    }
}
