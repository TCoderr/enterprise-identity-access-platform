using Npgsql;

namespace Halka.TestKit;

public sealed class TestDatabaseGuardException(string message) : InvalidOperationException(message);

/// <summary>
/// Refuses to let the test harness write (migrate, seed, clean up) anywhere except a database this test run created
/// itself. A name prefix alone is not trusted. All three conditions must hold:
/// 1. explicit opt-in through an environment variable,
/// 2. an ownership marker row carrying this run's identifier inside the target database,
/// 3. the server identity (system identifier and port) recorded when the disposable server was started.
/// </summary>
public static class TestDatabaseGuard
{
    public const string OptInVariable = "HALKA_TEST_ALLOW_DB_WRITES";
    public const string DatabasePrefix = "halka_test_";
    public const string MarkerTable = "__halka_test_owner";

    public static async Task MarkOwnedAsync(string ownerConnectionString, Guid runId, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(ownerConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE TABLE {MarkerTable} (run_id uuid PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now()); INSERT INTO {MarkerTable} (run_id) VALUES (@run)";
        command.Parameters.AddWithValue("run", runId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public static async Task EnsureOwnedAsync(
        string connectionString,
        Guid runId,
        string expectedSystemIdentifier,
        int expectedPort,
        CancellationToken cancellationToken = default)
    {
        if (Environment.GetEnvironmentVariable(OptInVariable) != "1")
        {
            throw new TestDatabaseGuardException($"Test database writes are not enabled ({OptInVariable} is not set to 1).");
        }

        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        if (builder.Database is null || !builder.Database.StartsWith(DatabasePrefix, StringComparison.Ordinal))
        {
            throw new TestDatabaseGuardException("The target database does not use the disposable test prefix.");
        }

        if (builder.Port != expectedPort)
        {
            throw new TestDatabaseGuardException("The target port is not the port of the disposable server started by this run.");
        }

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using (var identity = connection.CreateCommand())
        {
            identity.CommandText = "SELECT system_identifier::text FROM pg_control_system()";
            var actual = (string?)await identity.ExecuteScalarAsync(cancellationToken);
            if (!string.Equals(actual, expectedSystemIdentifier, StringComparison.Ordinal))
            {
                throw new TestDatabaseGuardException("The target server is not the disposable server started by this run.");
            }
        }

        await using (var marker = connection.CreateCommand())
        {
            marker.CommandText = "SELECT to_regclass(@name) IS NOT NULL";
            marker.Parameters.AddWithValue("name", MarkerTable);
            if (await marker.ExecuteScalarAsync(cancellationToken) is not true)
            {
                throw new TestDatabaseGuardException("The target database has no ownership marker.");
            }
        }

        await using (var owner = connection.CreateCommand())
        {
            owner.CommandText = $"SELECT count(*) FROM {MarkerTable} WHERE run_id = @run";
            owner.Parameters.AddWithValue("run", runId);
            if (await owner.ExecuteScalarAsync(cancellationToken) is not 1L)
            {
                throw new TestDatabaseGuardException("The target database is owned by a different test run.");
            }
        }
    }
}
