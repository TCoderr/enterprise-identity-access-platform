using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Halka.DemoClient;

/// <summary>
/// Server-side application session. The browser cookie only references this row; the tokens live here, encrypted
/// with Data Protection, and never reach the browser.
/// </summary>
public sealed class AppSession
{
    public Guid Id { get; set; }

    public string Subject { get; set; } = string.Empty;

    public byte[] ProtectedTokens { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Incremented on every token update (optimistic concurrency for refresh).</summary>
    public int Version { get; set; }
}

public sealed record TokenSet(string AccessToken, string? RefreshToken, string? IdToken, DateTimeOffset ExpiresAt, IReadOnlyList<string> Scopes);

public sealed record StoredSession(Guid Id, int Version, TokenSet Tokens);

public sealed class ClientDbContext(DbContextOptions<ClientDbContext> options) : DbContext(options)
{
    public DbSet<AppSession> AppSessions => Set<AppSession>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AppSession>(entity =>
        {
            entity.ToTable("app_sessions");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.Subject).HasMaxLength(64);
            entity.Property(x => x.Version).IsConcurrencyToken();
            entity.HasIndex(x => x.Subject);
        });
    }

    public static void Configure(DbContextOptionsBuilder options, string connectionString)
    {
        // The session store only issues single statements, so transient failures (for example a pooled connection
        // that died with a restarted database) can be retried safely on a new connection.
        options.UseNpgsql(connectionString, npgsql => npgsql
            .MigrationsAssembly(typeof(ClientDbContext).Assembly.GetName().Name)
            .EnableRetryOnFailure(maxRetryCount: 2, maxRetryDelay: TimeSpan.FromSeconds(1), errorCodesToAdd: null));
        options.UseSnakeCaseNamingConvention();
    }

    /// <summary>Drops pooled connections after an outage was noticed; see the 503 middleware and the readiness check.</summary>
    public void DropIdleConnections()
    {
        if (Database.GetDbConnection() is Npgsql.NpgsqlConnection connection)
        {
            Npgsql.NpgsqlConnection.ClearPool(connection);
        }
    }
}

/// <summary>Readiness of a demo client: its session store must be reachable.</summary>
public sealed class ClientDatabaseHealthCheck(ClientDbContext db) : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    public async Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            if (await db.Database.CanConnectAsync(timeout.Token))
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy();
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
        }

        db.DropIdleConnections();
        return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy();
    }
}

/// <summary>Used only by "dotnet ef" at design time; it never connects to a database.</summary>
public sealed class ClientDesignTimeDbContextFactory : IDesignTimeDbContextFactory<ClientDbContext>
{
    public ClientDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<ClientDbContext>();
        ClientDbContext.Configure(options, "Host=design-time.invalid;Database=design;Username=design;Password=design");
        return new ClientDbContext(options.Options);
    }
}

/// <summary>Creates, reads, updates and deletes application sessions.</summary>
public sealed class AppSessionStore(ClientDbContext db, IDataProtectionProvider protection, TimeProvider time)
{
    private readonly IDataProtector _protector = protection.CreateProtector("Halka.DemoClient.Tokens.v1");

    public async Task<Guid> CreateAsync(string subject, TokenSet tokens, CancellationToken cancellationToken)
    {
        var session = new AppSession
        {
            Id = Guid.NewGuid(),
            Subject = subject,
            ProtectedTokens = Protect(tokens),
            CreatedAt = time.GetUtcNow(),
            Version = 1,
        };
        db.AppSessions.Add(session);
        await db.SaveChangesAsync(cancellationToken);
        return session.Id;
    }

    public async Task<StoredSession?> FindAsync(Guid id, CancellationToken cancellationToken)
    {
        var row = await db.AppSessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        return row is null ? null : new StoredSession(row.Id, row.Version, Unprotect(row.ProtectedTokens));
    }

    /// <summary>Replaces the tokens when the row still has the expected version. Returns false when someone else won.</summary>
    public async Task<bool> TryUpdateAsync(Guid id, int expectedVersion, TokenSet tokens, CancellationToken cancellationToken)
    {
        var payload = Protect(tokens);
        var updated = await db.AppSessions
            .Where(x => x.Id == id && x.Version == expectedVersion)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.ProtectedTokens, payload)
                .SetProperty(x => x.Version, x => x.Version + 1), cancellationToken);
        return updated == 1;
    }

    public Task<int> DeleteAsync(Guid id, CancellationToken cancellationToken)
        => db.AppSessions.Where(x => x.Id == id).ExecuteDeleteAsync(cancellationToken);

    private byte[] Protect(TokenSet tokens) => _protector.Protect(JsonSerializer.SerializeToUtf8Bytes(tokens));

    private TokenSet Unprotect(byte[] payload)
        => JsonSerializer.Deserialize<TokenSet>(_protector.Unprotect(payload)) ?? throw new InvalidOperationException("The stored tokens could not be read.");
}

/// <summary>
/// One gate per application session. It serialises token refresh inside this process (single flight); the version
/// check in the store keeps a second instance from overwriting a newer token set.
/// </summary>
public sealed class SessionLocks
{
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _gates = new();

    public async Task<IDisposable> AcquireAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var gate = _gates.GetOrAdd(sessionId, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        return new Releaser(gate);
    }

    public void Forget(Guid sessionId) => _gates.TryRemove(sessionId, out _);

    private sealed class Releaser(SemaphoreSlim gate) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                gate.Release();
            }
        }
    }
}
