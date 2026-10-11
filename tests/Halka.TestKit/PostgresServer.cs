using Halka.Migrator;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Halka.TestKit;

public sealed record TestDatabase(
    string Name,
    string MigratorRole,
    string RuntimeRole,
    string MigratorConnectionString,
    string RuntimeConnectionString);

/// <summary>
/// One disposable PostgreSQL server (Testcontainers) per test process. Every stack gets its own databases and roles
/// on it. Nothing here ever targets a developer, shared or other project's database.
/// </summary>
public sealed class PostgresServer : IAsyncDisposable
{
    private static readonly Lazy<Task<PostgresServer>> SharedInstance = new(StartAsync);
    private static int _sequence;
    private readonly PostgreSqlContainer _container;

    private PostgresServer(PostgreSqlContainer container, string systemIdentifier)
    {
        _container = container;
        SystemIdentifier = systemIdentifier;
    }

    public static Task<PostgresServer> Shared => SharedInstance.Value;

    public Guid RunId { get; } = Guid.NewGuid();

    public string SystemIdentifier { get; }

    public string Host => _container.Hostname;

    public int Port => _container.GetMappedPublicPort(PostgreSqlBuilder.PostgreSqlPort);

    public string SuperuserConnectionString => _container.GetConnectionString();

    public string ContainerId => _container.Id;

    private static async Task<PostgresServer> StartAsync()
    {
        // The harness itself opts in; a stray connection string in a developer shell is not enough to pass the guard.
        Environment.SetEnvironmentVariable(TestDatabaseGuard.OptInVariable, "1");

        var container = new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase("postgres")
            .WithUsername("halka_test_superuser")
            .WithPassword(Guid.NewGuid().ToString("N"))
            .WithLabel("halka.test", "true")
            .Build();
        await container.StartAsync();

        await using var connection = new NpgsqlConnection(container.GetConnectionString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT system_identifier::text FROM pg_control_system()";
        var identifier = (string)(await command.ExecuteScalarAsync())!;
        return new PostgresServer(container, identifier);
    }

    /// <summary>Creates a database with its own owner and restricted runtime role and marks it as owned by this run.</summary>
    public async Task<TestDatabase> CreateDatabaseAsync(string purpose)
    {
        var suffix = $"{purpose}_{Interlocked.Increment(ref _sequence)}";
        var database = $"{TestDatabaseGuard.DatabasePrefix}{suffix}";
        var migratorRole = $"halka_test_migrator_{suffix}";
        var runtimeRole = $"halka_test_app_{suffix}";
        var migratorPassword = Guid.NewGuid().ToString("N");
        var runtimePassword = Guid.NewGuid().ToString("N");

        await using (var connection = new NpgsqlConnection(SuperuserConnectionString))
        {
            await connection.OpenAsync();
            foreach (var statement in BootstrapSql.Build(migratorRole, migratorPassword, [new DatabaseBootstrap(database, runtimeRole, runtimePassword)]))
            {
                await using var command = connection.CreateCommand();
                command.CommandText = statement;
                await command.ExecuteNonQueryAsync();
            }
        }

        var result = new TestDatabase(
            database,
            migratorRole,
            runtimeRole,
            ConnectionString(database, migratorRole, migratorPassword),
            ConnectionString(database, runtimeRole, runtimePassword));
        await TestDatabaseGuard.MarkOwnedAsync(result.MigratorConnectionString, RunId);
        return result;
    }

    public Task EnsureOwnedAsync(string connectionString)
        => TestDatabaseGuard.EnsureOwnedAsync(connectionString, RunId, SystemIdentifier, Port);

    public string ConnectionString(string database, string username, string password)
        => new NpgsqlConnectionStringBuilder
        {
            Host = Host,
            Port = Port,
            Database = database,
            Username = username,
            Password = password,
            Timeout = 5,
            CommandTimeout = 30,
            MaxPoolSize = 40,
            IncludeErrorDetail = true,
        }.ConnectionString;

    public Task PauseAsync() => _container.PauseAsync();

    public Task UnpauseAsync() => _container.UnpauseAsync();

    public ValueTask DisposeAsync() => _container.DisposeAsync();
}
