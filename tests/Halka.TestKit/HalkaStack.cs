using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Halka.Iam;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mail;
using Halka.Migrator;
using Halka.Pano;
using Halka.Rapor;
using Halka.WorkspaceApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Halka.TestKit;

public sealed record TestUser(Guid Id, string Email, string DisplayName, string Password);

public sealed record SinkMail(string MessageId, string Kind, string To, string Subject, string Link);

public sealed class StackOptions
{
    /// <summary>Extra IAM settings ("Section:Key" → value) applied on top of the test defaults.</summary>
    public Dictionary<string, string> IamSettings { get; } = new(StringComparer.Ordinal);

    /// <summary>Extra settings applied to both demo clients.</summary>
    public Dictionary<string, string> ClientSettings { get; } = new(StringComparer.Ordinal);

    /// <summary>Extra settings applied to the Workspace API.</summary>
    public Dictionary<string, string> ApiSettings { get; } = new(StringComparer.Ordinal);

    /// <summary>Runs the identity provider on a clock shifted by this amount relative to the other hosts.</summary>
    public TimeSpan IamClockOffset { get; set; }

    /// <summary>Routes the identity provider's database connections through a relay that tests can interrupt.</summary>
    public bool RelayIamDatabase { get; set; }

    /// <summary>Hook to replace services of a demo client host (used to intercept its back-channel in tests).</summary>
    public Action<string, WebApplicationBuilder>? ConfigureClient { get; set; }
}

/// <summary>
/// The system under test: real Kestrel HTTPS listeners on loopback using the product host names (identity provider,
/// two relying parties, resource API), disposable PostgreSQL databases reached through the restricted runtime
/// roles, and one controllable clock shared by all hosts.
/// </summary>
public sealed class HalkaStack : IAsyncDisposable
{
    public const string IamHostName = "id.halka.localhost";
    public const string PanoHostName = "pano.localhost";
    public const string RaporHostName = "rapor.localhost";
    public const string ApiHostName = "workspace-api.localhost";

    private readonly StackOptions _options;
    private readonly string _workDirectory;
    private readonly int _iamPort = FreePort();
    private readonly int _panoPort = FreePort();
    private readonly int _raporPort = FreePort();
    private readonly int _apiPort = FreePort();
    private ServiceProvider? _migratorServices;

    private HalkaStack(StackOptions options, PostgresServer postgres)
    {
        _options = options;
        Postgres = postgres;
        _workDirectory = Path.Combine(Path.GetTempPath(), "halka-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDirectory);
        Pki = new TestPki(Path.Combine(_workDirectory, "pki"));
        Demo = new DemoSeed(PanoOrigin, RaporOrigin, Secret(), Secret(), Secret(), Secret());
        IamTime = options.IamClockOffset == TimeSpan.Zero ? Time : new FakeTimeProvider(Time.GetUtcNow() + options.IamClockOffset);

        static string Secret() => Halka.Iam.Clients.ClientRegistry.GenerateSecret();
    }

    public PostgresServer Postgres { get; }

    public TestPki Pki { get; }

    public FakeTimeProvider Time { get; } = new(DateTimeOffset.UtcNow);

    /// <summary>Clock of the identity provider; the same instance as <see cref="Time"/> unless an offset was requested.</summary>
    public FakeTimeProvider IamTime { get; }

    public CapturingLoggerProvider Logs { get; } = new();

    public DemoSeed Demo { get; }

    public TestDatabase IamDatabase { get; private set; } = null!;

    public TestDatabase PanoDatabase { get; private set; } = null!;

    public TestDatabase RaporDatabase { get; private set; } = null!;

    /// <summary>Present when <see cref="StackOptions.RelayIamDatabase"/> is set; stopping it simulates a database outage.</summary>
    public TcpRelay? IamDatabaseRelay { get; private set; }

    public WebApplication Iam { get; private set; } = null!;

    public WebApplication Pano { get; private set; } = null!;

    public WebApplication Rapor { get; private set; } = null!;

    public WebApplication Api { get; private set; } = null!;

    public string IamOrigin => $"https://{IamHostName}:{_iamPort}";

    public string PanoOrigin => $"https://{PanoHostName}:{_panoPort}";

    public string RaporOrigin => $"https://{RaporHostName}:{_raporPort}";

    public string ApiOrigin => $"https://{ApiHostName}:{_apiPort}";

    public string MailSinkDirectory => Path.Combine(_workDirectory, "mail-sink");

    public static async Task<HalkaStack> StartAsync(StackOptions? options = null)
    {
        var stack = new HalkaStack(options ?? new StackOptions(), await PostgresServer.Shared);
        await stack.InitializeAsync();
        return stack;
    }

    private async Task InitializeAsync()
    {
        IamDatabase = await Postgres.CreateDatabaseAsync("iam");
        PanoDatabase = await Postgres.CreateDatabaseAsync("pano");
        RaporDatabase = await Postgres.CreateDatabaseAsync("rapor");
        _migratorServices = MigratorRunner.BuildIamServices(MigratorConfiguration(IamDatabase.MigratorConnectionString));
        await MigrateGuardedAsync(Postgres, _migratorServices, IamDatabase.MigratorConnectionString, IamDatabase.RuntimeRole, Demo);
        foreach (var database in new[] { PanoDatabase, RaporDatabase })
        {
            await Postgres.EnsureOwnedAsync(database.MigratorConnectionString);
            await MigratorRunner.MigrateClientAsync(database.MigratorConnectionString, database.RuntimeRole, CancellationToken.None);
        }

        await StartIamAsync();
        await StartApiAsync();
        await StartPanoAsync();
        await StartRaporAsync();
    }

    /// <summary>
    /// The only path through which the harness changes the identity schema or seeds data. The ownership guard runs
    /// first; when it refuses, nothing is written to the target.
    /// </summary>
    public static async Task MigrateGuardedAsync(PostgresServer postgres, IServiceProvider migratorServices, string connectionString, string runtimeRole, DemoSeed? demo = null)
    {
        await postgres.EnsureOwnedAsync(connectionString);
        await MigratorRunner.MigrateIamAsync(migratorServices, runtimeRole, CancellationToken.None);
        await MigratorRunner.SeedIamAsync(migratorServices, SeedData.Empty, demo, CancellationToken.None);
    }

    /// <summary>Configuration for a migrator service graph that targets <paramref name="connectionString"/>.</summary>
    public IConfiguration MigratorConfiguration(string connectionString)
        => new ConfigurationBuilder().AddInMemoryCollection(IamSettings(connectionString)!).Build();

    /// <summary>Starts (or restarts) the identity provider with the same keys, database and configuration.</summary>
    public async Task StartIamAsync()
    {
        var certificate = Pki.IssueServerCertificate(IamHostName);
        var connectionString = IamDatabase.RuntimeConnectionString;
        if (_options.RelayIamDatabase)
        {
            IamDatabaseRelay ??= TcpRelay.Start(Postgres.Host, Postgres.Port);
            connectionString = new Npgsql.NpgsqlConnectionStringBuilder(connectionString) { Host = "127.0.0.1", Port = IamDatabaseRelay.Port, Timeout = 3 }.ConnectionString;
        }

        Iam = IamHost.Build(Arguments(IamSettings(connectionString)), builder =>
        {
            ConfigureHost(builder, _iamPort, certificate);
            builder.Services.RemoveAll<TimeProvider>();
            builder.Services.AddSingleton<TimeProvider>(IamTime);
        });
        await Iam.StartAsync();
    }

    public async Task StopIamAsync()
    {
        await Iam.StopAsync();
        await Iam.DisposeAsync();
    }

    public async Task StartApiAsync()
    {
        var settings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Api:Authority"] = IamOrigin,
            ["Api:ClientSecret"] = Demo.WorkspaceApiSecret,
            ["AllowedHosts"] = ApiHostName,
        };
        AddBackchannel(settings);
        Overlay(settings, _options.ApiSettings);
        var certificate = Pki.IssueServerCertificate(ApiHostName);
        Api = WorkspaceApiHost.Build(Arguments(settings), builder => ConfigureHost(builder, _apiPort, certificate));
        await Api.StartAsync();
    }

    public async Task StartPanoAsync()
    {
        var certificate = Pki.IssueServerCertificate(PanoHostName);
        Pano = PanoApp.Build(
            Arguments(ClientSettings("pano", PanoOrigin, DemoCatalog.PanoClientId, Demo.PanoSecret, PanoDatabase, PanoHostName)),
            builder =>
            {
                ConfigureHost(builder, _panoPort, certificate);
                _options.ConfigureClient?.Invoke("pano", builder);
            });
        await Pano.StartAsync();
    }

    public async Task StartRaporAsync()
    {
        var certificate = Pki.IssueServerCertificate(RaporHostName);
        Rapor = RaporApp.Build(
            Arguments(ClientSettings("rapor", RaporOrigin, DemoCatalog.RaporClientId, Demo.RaporSecret, RaporDatabase, RaporHostName)),
            builder =>
            {
                ConfigureHost(builder, _raporPort, certificate);
                _options.ConfigureClient?.Invoke("rapor", builder);
            });
        await Rapor.StartAsync();
    }

    public Browser NewBrowser(IPAddress? sourceAddress = null) => new(Pki.Authority, sourceAddress: sourceAddress);

    /// <summary>Delivers every queued demo mail.</summary>
    public async Task DrainMailAsync()
    {
        while (await DispatchMailAsync() > 0)
        {
        }
    }

    /// <summary>Runs code against the running identity provider's services (restricted runtime database role).</summary>
    public async Task<T> InIamAsync<T>(Func<IServiceProvider, Task<T>> action)
    {
        await using var scope = Iam.Services.CreateAsyncScope();
        return await action(scope.ServiceProvider);
    }

    public Task InIamAsync(Func<IServiceProvider, Task> action)
        => InIamAsync(async services =>
        {
            await action(services);
            return true;
        });

    /// <summary>Runs code with the owner (migration) role, e.g. to arrange data the runtime role may not change.</summary>
    public async Task<T> AsOwnerAsync<T>(Func<IServiceProvider, Task<T>> action)
    {
        await Postgres.EnsureOwnedAsync(IamDatabase.MigratorConnectionString);
        await using var scope = _migratorServices!.CreateAsyncScope();
        return await action(scope.ServiceProvider);
    }

    /// <summary>Creates a confirmed account directly (most tests do not need the sign-up flow).</summary>
    public Task<TestUser> CreateUserAsync(params string[] roles)
        => InIamAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var id = Guid.NewGuid();
            var email = $"user-{id:N}@example.test";
            var password = $"Pw-{Guid.NewGuid():N}";
            var user = new ApplicationUser
            {
                Id = id,
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                DisplayName = $"Test User {id.ToString("N")[..6]}",
                CreatedAt = Time.GetUtcNow(),
                LockoutEnabled = true,
            };
            Require(await users.CreateAsync(user, password));
            foreach (var role in roles.Append(Roles.User).Distinct(StringComparer.Ordinal))
            {
                Require(await users.AddToRoleAsync(user, role));
            }

            return new TestUser(id, email, user.DisplayName, password);
        });

    /// <summary>Signs a user in through the real login form and returns the landing page.</summary>
    public async Task<Page> SignInAsync(Browser browser, TestUser user, string? returnUrl = null)
    {
        var url = $"{IamOrigin}/account/login" + (returnUrl is null ? string.Empty : $"?returnUrl={Uri.EscapeDataString(returnUrl)}");
        var login = await browser.GetAsync(url);
        return await browser.SubmitAsync(login, "form[action*='/account/login']", new Dictionary<string, string>
        {
            ["Input.Email"] = user.Email,
            ["Input.Password"] = user.Password,
        });
    }

    /// <summary>Delivers queued demo mail now (the background worker is disabled in tests for determinism).</summary>
    public Task<int> DispatchMailAsync()
        => InIamAsync(services => services.GetRequiredService<OutboxDispatcher>().DispatchOnceAsync("test-dispatcher", CancellationToken.None));

    public IReadOnlyList<SinkMail> ReadMailSink()
    {
        if (!Directory.Exists(MailSinkDirectory))
        {
            return [];
        }

        return Directory.GetFiles(MailSinkDirectory, "*.json")
            .Select(path => JsonSerializer.Deserialize<SinkMail>(File.ReadAllText(path), new JsonSerializerOptions(JsonSerializerDefaults.Web))!)
            .ToList();
    }

    public async Task<SinkMail> ReceiveMailAsync(string to, string kind)
    {
        await DispatchMailAsync();
        return ReadMailSink().LastOrDefault(mail => mail.To == to && mail.Kind == kind)
               ?? throw new InvalidOperationException($"No '{kind}' mail was delivered to the sink for the requested address.");
    }

    private void ConfigureHost(WebApplicationBuilder builder, int port, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
    {
        builder.Services.RemoveAll<TimeProvider>();
        builder.Services.AddSingleton<TimeProvider>(Time);
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(Logs);
        builder.Logging.SetMinimumLevel(LogLevel.Information);
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port, listen => listen.UseHttps(certificate)));
    }

    private Dictionary<string, string> IamSettings(string connectionString)
    {
        var settings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Iam:PublicOrigin"] = IamOrigin,
            ["Database:ConnectionString"] = connectionString,
            ["DataProtection:KeyDirectory"] = Path.Combine(_workDirectory, "dp-iam"),
            ["Mail:SinkDirectory"] = MailSinkDirectory,
            ["Mail:WorkerEnabled"] = "false",
            ["Retention:WorkerEnabled"] = "false",
            ["RateLimits:LoginPerAccountPerMinute"] = "100000",
            ["RateLimits:LoginPerAddressPerMinute"] = "100000",
            ["RateLimits:MfaPerMinute"] = "100000",
            ["RateLimits:RecoveryPerMinute"] = "100000",
            ["RateLimits:SignupPerHour"] = "100000",
            ["RateLimits:TokenPerMinute"] = "100000",
            ["AllowedHosts"] = IamHostName,
        };
        AddBackchannel(settings);
        Overlay(settings, _options.IamSettings);
        return settings;
    }

    private Dictionary<string, string> ClientSettings(string slug, string origin, string clientId, string secret, TestDatabase database, string host)
    {
        var settings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Client:PublicOrigin"] = origin,
            ["Client:Authority"] = IamOrigin,
            ["Client:ClientId"] = clientId,
            ["Client:ClientSecret"] = secret,
            ["Client:ApiBaseUrl"] = ApiOrigin,
            ["Database:ConnectionString"] = database.RuntimeConnectionString,
            ["DataProtection:KeyDirectory"] = Path.Combine(_workDirectory, $"dp-{slug}"),
            ["AllowedHosts"] = host,
        };
        AddBackchannel(settings);
        Overlay(settings, _options.ClientSettings);
        return settings;
    }

    private void AddBackchannel(Dictionary<string, string> settings)
    {
        settings["Backchannel:CaCertificatePath"] = Pki.AuthorityPemPath;
        settings["Backchannel:LocalhostSubdomainsToLoopback"] = "true";
        settings["Backchannel:TimeoutSeconds"] = "5";
    }

    private static void Overlay(Dictionary<string, string> settings, Dictionary<string, string> overrides)
    {
        foreach (var (key, value) in overrides)
        {
            settings[key] = value;
        }
    }

    private static string[] Arguments(Dictionary<string, string> settings)
        => settings.Select(pair => $"--{pair.Key}={pair.Value}").Append($"--environment={IamHost.TestingEnvironment}").ToArray();

    private static void Require(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"Test arrangement failed: {string.Join(", ", result.Errors.Select(error => error.Code))}");
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var app in new[] { Rapor, Pano, Api, Iam })
        {
            try
            {
                if (app is not null)
                {
                    await app.StopAsync();
                    await app.DisposeAsync();
                }
            }
            catch (Exception exception) when (exception is ObjectDisposedException or OperationCanceledException)
            {
            }
        }

        if (_migratorServices is not null)
        {
            await _migratorServices.DisposeAsync();
        }

        if (IamDatabaseRelay is not null)
        {
            await IamDatabaseRelay.DisposeAsync();
        }

        Pki.Dispose();
        try
        {
            Directory.Delete(_workDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
