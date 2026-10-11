using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mfa;
using Halka.Iam.Sessions;
using Halka.Migrator;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Halka.IntegrationTests.Stage9;

/// <summary>
/// Schema upgrade paths. Each test creates its own disposable database on the test server; the ownership guard is
/// checked before anything is written.
/// </summary>
[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Database)]
public sealed class MigrationUpgradeTests(StackFixture fixture)
{
    private const string Stage1 = "InitialIdentityAndSessions";
    private const string Stage3 = "Protocol";

    private HalkaStack Stack => fixture.Stack;

    private static async Task<T> ScalarAsync<T>(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (T)(await command.ExecuteScalarAsync())!;
    }

    private static async Task ExecuteAsync(string connectionString, string sql, params (string Name, object Value)[] parameters)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        await command.ExecuteNonQueryAsync();
    }

    private static async Task MigrateToAsync(IServiceProvider services, string? target)
    {
        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IamDbContext>().Database.GetService<IMigrator>().MigrateAsync(target);
    }

    [Fact]
    public async Task Upgrade_FromTheStage1AndStage3Schemas_KeepsExistingData_AndTheResultIsUsable()
    {
        var database = await Stack.Postgres.CreateDatabaseAsync("upgrade");
        await Stack.Postgres.EnsureOwnedAsync(database.MigratorConnectionString);
        var owner = database.MigratorConnectionString;
        await using var services = MigratorRunner.BuildIamServices(Stack.MigratorConfiguration(owner));

        // Stage 1 schema with data written the way that version stored it (plain SQL, only its columns).
        await MigrateToAsync(services, Stage1);
        Assert.False(await ScalarAsync<bool>(owner, "SELECT to_regclass('public.consents') IS NOT NULL"));
        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var email = $"legacy-{userId:N}@example.test";
        var password = $"Pw-{Guid.NewGuid():N}";
        var now = DateTimeOffset.UtcNow;
        var hash = new PasswordHasher<ApplicationUser>().HashPassword(new ApplicationUser(), password);
        await ExecuteAsync(owner, """
            INSERT INTO roles (id, name, normalized_name, concurrency_stamp) VALUES (@role, 'User', 'USER', 'seed');
            INSERT INTO users (id, display_name, is_disabled, created_at, user_name, normalized_user_name, email, normalized_email,
                               email_confirmed, password_hash, security_stamp, concurrency_stamp, phone_number_confirmed,
                               two_factor_enabled, lockout_enabled, access_failed_count)
            VALUES (@user, 'Legacy Person', false, @now, @email, upper(@email), @email, upper(@email), true, @hash, 'stamp', 'stamp', false, false, true, 0);
            INSERT INTO user_roles (user_id, role_id) VALUES (@user, @role);
            INSERT INTO user_sessions (id, user_id, created_at, auth_time, amr, password_verified_at, last_seen_at, absolute_expires_at, client_label)
            VALUES (@session, @user, @now, @now, 'pwd', @now, @now, @expires, 'Chrome on Windows');
            INSERT INTO one_time_tokens (id, user_id, purpose, token_hash, created_at, expires_at)
            VALUES (gen_random_uuid(), @user, 'reset_password', sha256('legacy-token'::bytea), @now, @expires);
            INSERT INTO audit_events (occurred_at, actor_type, actor_id, action, target_type, target_id, outcome)
            VALUES (@now, 'user', @userText, 'session.started', 'session', @sessionText, 'success');
            """,
            ("role", roleId), ("user", userId), ("session", sessionId), ("email", email), ("hash", hash), ("now", now),
            ("expires", now.AddHours(6)), ("userText", userId.ToString()), ("sessionText", sessionId.ToString()));

        // Stage 3 adds the protocol tables. Existing rows are untouched; a consent of that era is added.
        await MigrateToAsync(services, Stage3);
        Assert.Equal(1L, await ScalarAsync<long>(owner, $"SELECT count(*) FROM user_sessions WHERE id = '{sessionId}' AND revoked_at IS NULL"));
        Assert.False(await ScalarAsync<bool>(owner, "SELECT to_regclass('public.user_mfa') IS NOT NULL"));
        await ExecuteAsync(owner,
            "INSERT INTO consents (id, user_id, client_id, scopes, granted_at, updated_at) VALUES (gen_random_uuid(), @user, 'legacy-client', 'openid profile', @now, @now)",
            ("user", userId), ("now", now));

        // Latest schema through the same guarded path the product uses, including grants and seed.
        await HalkaStack.MigrateGuardedAsync(Stack.Postgres, services, owner, database.RuntimeRole, Stack.Demo);

        await using (var scope = services.CreateAsyncScope())
        {
            Assert.Empty(await scope.ServiceProvider.GetRequiredService<IamDbContext>().Database.GetPendingMigrationsAsync());
        }

        Assert.Equal(1L, await ScalarAsync<long>(owner, "SELECT count(*) FROM roles WHERE normalized_name = 'USER'"));
        Assert.Equal(1L, await ScalarAsync<long>(owner, $"SELECT count(*) FROM audit_events WHERE actor_id = '{userId}' AND action = 'session.started'"));
        Assert.Equal(1L, await ScalarAsync<long>(owner, $"SELECT count(*) FROM one_time_tokens WHERE user_id = '{userId}' AND consumed_at IS NULL"));
        Assert.Equal("openid profile", await ScalarAsync<string>(owner, $"SELECT scopes FROM consents WHERE user_id = '{userId}' AND client_id = 'legacy-client'"));

        // The upgraded data works with the current code, through the restricted runtime role.
        await using var runtime = MigratorRunner.BuildIamServices(Stack.MigratorConfiguration(database.RuntimeConnectionString));
        await using var runtimeScope = runtime.CreateAsyncScope();
        var users = runtimeScope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var legacy = await users.FindByEmailAsync(email);
        Assert.NotNull(legacy);
        Assert.Equal("Legacy Person", legacy.DisplayName);
        Assert.True(await users.CheckPasswordAsync(legacy, password));
        Assert.Equal([Roles.User], await users.GetRolesAsync(legacy));
        var session = (await runtimeScope.ServiceProvider.GetRequiredService<SessionService>().LoadAsync(sessionId, userId, CancellationToken.None)).Session;
        Assert.NotNull(session);
        Assert.Equal(email, session.Email);
        Assert.False(await runtimeScope.ServiceProvider.GetRequiredService<MfaService>().IsEnabledAsync(userId, CancellationToken.None));
        Assert.Equal(4, await runtimeScope.ServiceProvider.GetRequiredService<IamDbContext>().Applications.CountAsync());
    }

    [Fact]
    public async Task IdempotentScript_AppliedTwice_ProducesTheSameSchemaAsTheMigrator()
    {
        var scripted = await Stack.Postgres.CreateDatabaseAsync("script");
        var migrated = await Stack.Postgres.CreateDatabaseAsync("reference");
        await Stack.Postgres.EnsureOwnedAsync(scripted.MigratorConnectionString);
        await Stack.Postgres.EnsureOwnedAsync(migrated.MigratorConnectionString);

        await using var reference = MigratorRunner.BuildIamServices(Stack.MigratorConfiguration(migrated.MigratorConnectionString));
        await MigrateToAsync(reference, target: null);

        // The same script "dotnet ef migrations script --idempotent" produces, applied to an empty database twice.
        string script;
        int migrationCount;
        await using (var scope = reference.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<IamDbContext>().Database;
            script = database.GetService<IMigrator>().GenerateScript(options: MigrationsSqlGenerationOptions.Idempotent);
            migrationCount = database.GetMigrations().Count();
        }

        await ExecuteAsync(scripted.MigratorConnectionString, script);
        var afterFirst = await SchemaAsync(scripted.MigratorConnectionString);
        await ExecuteAsync(scripted.MigratorConnectionString, script);
        var afterSecond = await SchemaAsync(scripted.MigratorConnectionString);

        Assert.Equal(afterFirst, afterSecond);
        Assert.Equal(await SchemaAsync(migrated.MigratorConnectionString), afterSecond);
        Assert.Equal((long)migrationCount, await ScalarAsync<long>(scripted.MigratorConnectionString, "SELECT count(*) FROM \"__EFMigrationsHistory\""));
        Assert.True(afterSecond.Count > 150, $"expected a full schema description, got {afterSecond.Count} entries");
    }

    /// <summary>Columns, constraints and indexes of the public schema as comparable text lines.</summary>
    private static async Task<List<string>> SchemaAsync(string connectionString)
    {
        const string sql = """
            SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type || coalesce('(' || character_maximum_length || ')', '')
                   || ' null=' || is_nullable || ' default=' || coalesce(column_default, '') || ' identity=' || coalesce(identity_generation, '')
              FROM information_schema.columns WHERE table_schema = 'public' AND table_name <> '__halka_test_owner'
            UNION ALL
            SELECT 'constraint ' || conrelid::regclass || ' ' || conname || ' ' || pg_get_constraintdef(oid)
              FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND conrelid::regclass::text <> '__halka_test_owner'
            UNION ALL
            SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename <> '__halka_test_owner'
            ORDER BY 1
            """;
        var lines = new List<string>();
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            lines.Add(reader.GetString(0));
        }

        return lines;
    }
}
