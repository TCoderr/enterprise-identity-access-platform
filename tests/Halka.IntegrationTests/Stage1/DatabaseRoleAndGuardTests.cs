using Halka.Iam.Data;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Halka.IntegrationTests.Stage1;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Database)]
public sealed class DatabaseRoleAndGuardTests(StackFixture fixture)
{
    private const string InsufficientPrivilege = "42501";

    private HalkaStack Stack => fixture.Stack;

    private async Task<string?> ExecuteAsRuntimeAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(Stack.IamDatabase.RuntimeConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        try
        {
            await command.ExecuteNonQueryAsync();
            return null;
        }
        catch (PostgresException exception)
        {
            return exception.SqlState;
        }
    }

    [Fact]
    public async Task DbRoles_RuntimeRole_CannotChangeTheSchema()
    {
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync("CREATE TABLE runtime_probe (id int)"));
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync("ALTER TABLE users ADD COLUMN probe int"));
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync("DROP TABLE user_sessions"));
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync("CREATE SCHEMA runtime_probe"));
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync("SELECT * FROM \"__EFMigrationsHistory\""));
    }

    [Fact]
    public async Task DbRoles_AuditTable_IsAppendOnlyForTheRuntimeRole()
    {
        var action = $"test.probe.{Guid.NewGuid():N}";
        Assert.Null(await ExecuteAsRuntimeAsync(
            $"INSERT INTO audit_events (occurred_at, actor_type, action, outcome) VALUES (now(), 'system', '{action}', 'success')"));
        Assert.Null(await ExecuteAsRuntimeAsync("SELECT count(*) FROM audit_events"));

        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync($"UPDATE audit_events SET outcome = 'failure' WHERE action = '{action}'"));
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync($"DELETE FROM audit_events WHERE action = '{action}'"));
        Assert.Equal(InsufficientPrivilege, await ExecuteAsRuntimeAsync("TRUNCATE audit_events"));

        var stillThere = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents.CountAsync(x => x.Action == action && x.Outcome == "success"));
        Assert.Equal(1, stillThere);
    }

    [Fact]
    public async Task DbRoles_RuntimeRole_HasNoElevatedAttributes()
    {
        await using var connection = new NpgsqlConnection(Stack.IamDatabase.RuntimeConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname = current_user";
        Assert.Equal(false, await command.ExecuteScalarAsync());

        command.CommandText = "SELECT has_database_privilege(current_user, current_database(), 'CREATE')";
        Assert.Equal(false, await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task Migration_ModelHasNoPendingChanges_AndReapplyingIsANoOp()
    {
        await Stack.AsOwnerAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            Assert.False(db.Database.HasPendingModelChanges());
            Assert.Empty(await db.Database.GetPendingMigrationsAsync());
            return true;
        });

        // Running the migrator again (migrations, grants and seed) changes nothing and does not fail.
        await using var again = MigratorRunner.BuildIamServices(Stack.MigratorConfiguration(Stack.IamDatabase.MigratorConnectionString));
        await HalkaStack.MigrateGuardedAsync(Stack.Postgres, again, Stack.IamDatabase.MigratorConnectionString, Stack.IamDatabase.RuntimeRole);
    }

    [Fact]
    public async Task TestGuard_WrongTarget_IsRefusedAndNothingIsWritten()
    {
        var postgres = Stack.Postgres;

        // A database on the same disposable server that this run did not mark as its own.
        var unowned = $"{TestDatabaseGuard.DatabasePrefix}unowned_{Guid.NewGuid():N}"[..40];
        await using (var admin = new NpgsqlConnection(postgres.SuperuserConnectionString))
        {
            await admin.OpenAsync();
            await using var create = admin.CreateCommand();
            create.CommandText = $"CREATE DATABASE {unowned}";
            await create.ExecuteNonQueryAsync();
        }

        var superuser = new NpgsqlConnectionStringBuilder(postgres.SuperuserConnectionString);
        var unownedConnection = new NpgsqlConnectionStringBuilder(postgres.SuperuserConnectionString) { Database = unowned }.ConnectionString;
        await using var services = MigratorRunner.BuildIamServices(Stack.MigratorConfiguration(unownedConnection));

        await Assert.ThrowsAsync<TestDatabaseGuardException>(() =>
            HalkaStack.MigrateGuardedAsync(postgres, services, unownedConnection, Stack.IamDatabase.RuntimeRole));

        await using (var check = new NpgsqlConnection(unownedConnection))
        {
            await check.OpenAsync();
            await using var count = check.CreateCommand();
            count.CommandText = "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')";
            Assert.Equal(0L, await count.ExecuteScalarAsync());
        }

        // Not the test prefix (the server's default database): refused before any connection is opened.
        await Assert.ThrowsAsync<TestDatabaseGuardException>(() => postgres.EnsureOwnedAsync(postgres.SuperuserConnectionString));

        // Owned by a different run identifier.
        await Assert.ThrowsAsync<TestDatabaseGuardException>(() => TestDatabaseGuard.EnsureOwnedAsync(
            Stack.IamDatabase.MigratorConnectionString, Guid.NewGuid(), postgres.SystemIdentifier, postgres.Port));

        // A different server identity or port.
        await Assert.ThrowsAsync<TestDatabaseGuardException>(() => TestDatabaseGuard.EnsureOwnedAsync(
            Stack.IamDatabase.MigratorConnectionString, postgres.RunId, "0000000000000000000", postgres.Port));
        await Assert.ThrowsAsync<TestDatabaseGuardException>(() => TestDatabaseGuard.EnsureOwnedAsync(
            Stack.IamDatabase.MigratorConnectionString, postgres.RunId, postgres.SystemIdentifier, superuser.Port + 1));

        // The legitimate target still passes.
        await postgres.EnsureOwnedAsync(Stack.IamDatabase.MigratorConnectionString);
    }
}
