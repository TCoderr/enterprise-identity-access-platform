using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Halka.Migrator;

namespace Halka.Smoke;

/// <summary>
/// Connection to the disposable Compose project started by scripts/smoke.ps1. The project name must be a
/// non-default "halka-*" project so these tests can never run against (or scan and restart) the developer stack.
/// </summary>
public sealed class SmokeEnvironment : IDisposable
{
    private SmokeEnvironment(string project, string localDirectory, int portBase)
    {
        Project = project;
        LocalDirectory = localDirectory;
        PortBase = portBase;
        Authority = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(localDirectory, "tls", "ca.crt"));
        Seed = SeedData.Load(Path.Combine(localDirectory, "seed", "credentials.json"));
    }

    public static SmokeEnvironment Current { get; } = Load();

    public string Project { get; }

    public string LocalDirectory { get; }

    public int PortBase { get; }

    public X509Certificate2 Authority { get; }

    public SeedData Seed { get; }

    public string IamOrigin => $"https://id.halka.localhost:{PortBase}";

    public string PanoOrigin => $"https://pano.localhost:{PortBase + 1}";

    public string RaporOrigin => $"https://rapor.localhost:{PortBase + 2}";

    public string ApiOrigin => $"https://workspace-api.localhost:{PortBase + 3}";

    public string ComposeFile { get; } = Environment.GetEnvironmentVariable("HALKA_SMOKE_COMPOSE_FILE") ?? string.Empty;

    /// <summary>Application services built from this repository (the database image is the upstream one).</summary>
    public static IReadOnlyList<string> AppServices { get; } = ["iam", "workspace-api", "pano", "rapor"];

    public string PanoStatePath => Path.Combine(LocalDirectory, "smoke-pano.json");

    public string MailSinkDirectory => Path.Combine(LocalDirectory, "mail-sink");

    public string StatePath => Path.Combine(LocalDirectory, "smoke-state.json");

    public Browser NewBrowser() => new(Authority);

    public TestUser SeedUser(string email)
    {
        var user = Seed.Users.Single(candidate => candidate.Email == email);
        return new TestUser(Guid.Empty, user.Email, user.DisplayName, user.Password);
    }

    /// <summary>Every secret value of the stack; used to prove that none of them appears in images or logs.</summary>
    public IReadOnlyDictionary<string, string> SecretValues()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in Directory.GetFiles(Path.Combine(LocalDirectory, "secrets")))
        {
            values[$"secrets/{Path.GetFileName(file)}"] = File.ReadAllText(file).Trim();
        }

        foreach (var user in Seed.Users)
        {
            values[$"seed-password/{user.Role}"] = user.Password;
        }

        return values;
    }

    public async Task<SinkMail> WaitForMailAsync(string to, string kind)
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        for (var attempt = 0; attempt < 60; attempt++)
        {
            if (Directory.Exists(MailSinkDirectory))
            {
                foreach (var path in Directory.GetFiles(MailSinkDirectory, "*.json"))
                {
                    try
                    {
                        var mail = JsonSerializer.Deserialize<SinkMail>(await File.ReadAllTextAsync(path), options);
                        if (mail is not null && mail.To == to && mail.Kind == kind)
                        {
                            return mail;
                        }
                    }
                    catch (IOException)
                    {
                        // The worker may be writing the file; it is retried on the next poll.
                    }
                }
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500));
        }

        throw new InvalidOperationException($"No '{kind}' mail arrived in the smoke mail sink within 30 seconds.");
    }

    public static async Task<(int ExitCode, string Output)> DockerAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("docker could not be started.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await output + await error);
    }

    public string Container(string service) => $"{Project}-{service}-1";

    /// <summary>Polls a URL until it answers with the expected status (services come back asynchronously).</summary>
    public static async Task<Page> WaitForStatusAsync(Browser browser, string url, System.Net.HttpStatusCode expected)
    {
        Page? page = null;
        for (var attempt = 0; attempt < 80; attempt++)
        {
            try
            {
                page = await browser.GetAsync(url);
                if (page.Status == expected)
                {
                    return page;
                }
            }
            catch (HttpRequestException)
            {
                // The container is still starting or stopping.
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500));
        }

        throw new InvalidOperationException($"{new Uri(url).GetLeftPart(UriPartial.Path)} did not answer {(int)expected} within 40 seconds (last: {(int?)page?.Status}).");
    }

    private static SmokeEnvironment Load()
    {
        var project = Environment.GetEnvironmentVariable("HALKA_SMOKE_PROJECT");
        var local = Environment.GetEnvironmentVariable("HALKA_SMOKE_LOCAL_DIR");
        var port = Environment.GetEnvironmentVariable("HALKA_SMOKE_PORT_BASE");
        if (string.IsNullOrWhiteSpace(project) || string.IsNullOrWhiteSpace(local) || !int.TryParse(port, out var portBase))
        {
            throw new InvalidOperationException("Smoke tests need HALKA_SMOKE_PROJECT, HALKA_SMOKE_LOCAL_DIR and HALKA_SMOKE_PORT_BASE. Run scripts/smoke.ps1.");
        }

        if (project == "halka" || !project.StartsWith("halka-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Smoke tests only run against a disposable 'halka-*' Compose project, never the default stack.");
        }

        return new SmokeEnvironment(project, local, portBase);
    }

    public void Dispose() => Authority.Dispose();
}
