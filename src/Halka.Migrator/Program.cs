using Halka.Migrator;
using Halka.Shared;
using Microsoft.Extensions.Configuration;

// Usage: Halka.Migrator <migrate|seed|up>
// Configuration comes from environment variables (see deploy/docker-compose.yml); secrets are read from mounted files.
var command = args.FirstOrDefault(argument => !argument.StartsWith('-')) ?? "up";
var configuration = new ConfigurationBuilder()
    .AddEnvironmentVariables()
    .AddCommandLine(args.Where(argument => argument.StartsWith('-')).ToArray())
    .Build();

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

if (command is not ("migrate" or "seed" or "up"))
{
    Console.Error.WriteLine($"Unknown command '{command}'. Use migrate, seed or up.");
    return 2;
}

try
{
    await using var services = MigratorRunner.BuildIamServices(configuration);
    var runtimeRole = configuration["Migrator:IamRuntimeRole"] ?? "halka_iam_app";

    if (command is "migrate" or "up")
    {
        await MigratorRunner.MigrateIamAsync(services, runtimeRole, cancellation.Token);
        Console.WriteLine("migrate: identity schema is up to date and runtime grants are applied.");
        foreach (var client in new[] { "Pano", "Rapor" })
        {
            var section = configuration.GetSection($"Migrator:{client}");
            if (section.GetSection("Database").Exists())
            {
                await MigratorRunner.MigrateClientAsync(
                    DatabaseSettings.BuildConnectionString(section.GetSection("Database")),
                    section["RuntimeRole"] ?? $"halka_{client.ToLowerInvariant()}_app",
                    cancellation.Token);
                Console.WriteLine($"migrate: {client} session schema is up to date.");
            }
        }
    }

    if (command is "seed" or "up")
    {
        var seedFile = configuration["Migrator:SeedFile"];
        var seed = string.IsNullOrWhiteSpace(seedFile) ? SeedData.Empty : SeedData.Load(seedFile);
        var demo = ReadDemoSeed(configuration.GetSection("Migrator:Demo"));
        await MigratorRunner.SeedIamAsync(services, seed, demo, cancellation.Token);
        Console.WriteLine($"seed: roles, protocol keys, {seed.Users.Count} bootstrap account(s){(demo is null ? string.Empty : " and demo clients")} are present.");
    }

    return 0;
}
catch (Exception exception)
{
    // Type and message only; connection strings and secrets are never part of these messages.
    Console.Error.WriteLine($"migrator failed: {exception.GetType().Name}: {exception.Message}");
    return 1;
}

static DemoSeed? ReadDemoSeed(IConfigurationSection section)
{
    var pano = section["PanoOrigin"];
    var rapor = section["RaporOrigin"];
    if (string.IsNullOrWhiteSpace(pano) || string.IsNullOrWhiteSpace(rapor))
    {
        return null;
    }

    return new DemoSeed(
        pano.TrimEnd('/'),
        rapor.TrimEnd('/'),
        Required(section, "PanoSecret"),
        Required(section, "RaporSecret"),
        Required(section, "WorkspaceApiSecret"),
        Required(section, "OpsMachineSecret"));

    static string Required(IConfigurationSection section, string key)
        => SecretFile.Resolve(section, key) ?? throw new InvalidOperationException($"Migrator:Demo:{key} (or {key}File) is not configured.");
}
