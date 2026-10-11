using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Halka.Migrator;

namespace Halka.LocalInit;

/// <summary>
/// Creates the private local material of a stack under a target directory (default ".local"): development CA and
/// TLS certificates, database passwords, client secrets, Data Protection wrapping certificates, the PostgreSQL
/// bootstrap script and the seed credentials. The operation is idempotent: existing files are never overwritten,
/// so re-running it keeps all keys, passwords and therefore all sessions and enrolled authenticators usable.
/// </summary>
public static class LocalInitializer
{
    public static readonly IReadOnlyDictionary<string, string> Hosts = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["iam"] = "id.halka.localhost",
        ["pano"] = "pano.localhost",
        ["rapor"] = "rapor.localhost",
        ["api"] = "workspace-api.localhost",
    };

    private static readonly string[] DatabaseSecrets = ["db-superuser", "db-migrator", "db-iam", "db-pano", "db-rapor"];
    private static readonly string[] ClientSecrets = ["client-pano", "client-rapor", "client-workspace-api", "client-ops-machine"];
    private static readonly string[] DataProtectionApps = ["iam", "pano", "rapor"];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static int Run(string[] args)
    {
        var target = Path.GetFullPath(ReadOption(args, "--target") ?? ".local");
        var log = new List<string>();
        try
        {
            Initialize(target, log);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"local init failed: {exception.GetType().Name}: {exception.Message}");
            return 1;
        }

        foreach (var line in log)
        {
            Console.WriteLine(line);
        }

        Console.WriteLine($"local init complete: {target}");
        return 0;
    }

    public static void Initialize(string target, List<string> log)
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-5);
        foreach (var directory in new[] { "tls", "secrets", "dp-wrap", "postgres/init", "seed", "mail-sink" })
        {
            EnsureDirectory(Path.Combine(target, directory), writableByContainers: directory == "mail-sink");
        }

        foreach (var app in DataProtectionApps)
        {
            EnsureDirectory(Path.Combine(target, "dp-keys", app), writableByContainers: true);
        }

        // Transport certificates.
        var caCertificatePath = Path.Combine(target, "tls", "ca.crt");
        var caKeyPath = Path.Combine(target, "tls", "ca.key");
        if (!File.Exists(caCertificatePath) || !File.Exists(caKeyPath))
        {
            using var created = DevPki.CreateAuthority("Halka ID Local Development CA", now, TimeSpan.FromDays(3650));
            WritePrivate(caCertificatePath, created.ExportCertificatePem(), log);
            WritePrivate(caKeyPath, DevPki.PrivateKeyPem(created), log);
        }

        using var authority = X509Certificate2.CreateFromPemFile(caCertificatePath, caKeyPath);
        foreach (var (name, host) in Hosts)
        {
            var certificatePath = Path.Combine(target, "tls", $"{name}.crt");
            var keyPath = Path.Combine(target, "tls", $"{name}.key");
            if (File.Exists(certificatePath) && File.Exists(keyPath))
            {
                continue;
            }

            using var leaf = DevPki.CreateServerCertificate(authority, [host], now, TimeSpan.FromDays(825));
            WritePrivate(certificatePath, leaf.ExportCertificatePem(), log);
            WritePrivate(keyPath, DevPki.PrivateKeyPem(leaf), log);
        }

        // Random secrets (system CSPRNG).
        foreach (var name in DatabaseSecrets.Concat(ClientSecrets))
        {
            WritePrivateIfMissing(Path.Combine(target, "secrets", name), () => RandomToken(32), log);
        }

        // Data Protection key-wrapping certificates: one per application, separate from TLS.
        foreach (var app in DataProtectionApps)
        {
            var passwordPath = Path.Combine(target, "secrets", $"dp-wrap-{app}");
            var pfxPath = Path.Combine(target, "dp-wrap", $"{app}.pfx");
            if (File.Exists(pfxPath) && File.Exists(passwordPath))
            {
                continue;
            }

            var password = RandomToken(32);
            using var wrapping = DevPki.CreateKeyWrappingCertificate($"Halka {app} Data Protection key wrapping", now, TimeSpan.FromDays(3650));
            WritePrivate(passwordPath, password, log);
            WritePrivateBytes(pfxPath, wrapping.Export(X509ContentType.Pfx, password), log);
        }

        // PostgreSQL bootstrap script (roles and databases). It runs only when the data volume is empty.
        var bootstrapPath = Path.Combine(target, "postgres", "init", "01-bootstrap.sql");
        if (!File.Exists(bootstrapPath))
        {
            var statements = BootstrapSql.Build(
                "halka_migrator",
                ReadSecret(target, "db-migrator"),
                [
                    new DatabaseBootstrap("halka_iam", "halka_iam_app", ReadSecret(target, "db-iam")),
                    new DatabaseBootstrap("halka_pano", "halka_pano_app", ReadSecret(target, "db-pano")),
                    new DatabaseBootstrap("halka_rapor", "halka_rapor_app", ReadSecret(target, "db-rapor")),
                ]);
            WritePrivate(bootstrapPath, string.Join(";\n", statements) + ";\n", log);
        }

        // Seed accounts. Passwords are generated here and exist only in this private file and as hashes in the database.
        var seedPath = Path.Combine(target, "seed", "credentials.json");
        if (!File.Exists(seedPath))
        {
            var seed = new SeedData(
            [
                new SeedUser("admin@halka.test", "Platform Admin", "PlatformAdmin", ReadablePassword()),
                new SeedUser("secadmin@halka.test", "Security Admin", "SecurityAdmin", ReadablePassword()),
                new SeedUser("appadmin@halka.test", "Application Admin", "ApplicationAdmin", ReadablePassword()),
                new SeedUser("alice@halka.test", "Alice Demo", "User", ReadablePassword()),
            ]);
            WritePrivate(seedPath, JsonSerializer.Serialize(seed, Json), log);
        }

        // Public manifest of what was generated (no secrets): hosts and certificate pins for tooling.
        var manifest = new
        {
            hosts = Hosts,
            caSpki = DevPki.SpkiHash(authority),
            leafSpki = Hosts.Keys.ToDictionary(
                name => name,
                name =>
                {
                    using var leaf = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(target, "tls", $"{name}.crt"));
                    return DevPki.SpkiHash(leaf);
                }),
        };
        File.WriteAllText(Path.Combine(target, "manifest.json"), JsonSerializer.Serialize(manifest, Json));
    }

    public static string RandomToken(int bytes) => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>A typeable password with about 120 bits of entropy, e.g. "hk-ABCDEF-GHJKLM-NPQRST-UVWXYZ".</summary>
    public static string ReadablePassword()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var builder = new StringBuilder("hk");
        for (var group = 0; group < 4; group++)
        {
            builder.Append('-');
            for (var index = 0; index < 6; index++)
            {
                builder.Append(alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]);
            }
        }

        return builder.ToString();
    }

    private static string ReadSecret(string target, string name) => File.ReadAllText(Path.Combine(target, "secrets", name)).Trim();

    private static string? ReadOption(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static void EnsureDirectory(string path, bool writableByContainers)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            // Containers run as a non-root user whose id differs from the host user. Development only.
            File.SetUnixFileMode(path, writableByContainers
                ? (UnixFileMode)0b111_111_111
                : UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        }
    }

    private static void WritePrivateIfMissing(string path, Func<string> content, List<string> log)
    {
        if (!File.Exists(path))
        {
            WritePrivate(path, content(), log);
        }
    }

    private static void WritePrivate(string path, string content, List<string> log)
        => WritePrivateBytes(path, Encoding.UTF8.GetBytes(content), log);

    private static void WritePrivateBytes(string path, byte[] content, List<string> log)
    {
        File.WriteAllBytes(path, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }

        log.Add($"created {path}");
    }
}
