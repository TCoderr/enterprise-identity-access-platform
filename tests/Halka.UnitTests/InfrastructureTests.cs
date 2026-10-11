using System.Security.Cryptography.X509Certificates;
using Halka.Iam.Identity;
using Halka.LocalInit;
using Halka.Migrator;
using Halka.Shared;
using Microsoft.Extensions.Configuration;

namespace Halka.UnitTests;

public sealed class InfrastructureTests
{
    [Theory]
    [InlineData("halka_iam_app")]
    [InlineData("_role1")]
    public void BootstrapSql_AcceptsPlainIdentifiers(string value) => Assert.Equal(value, BootstrapSql.Identifier(value));

    [Theory]
    [InlineData("")]
    [InlineData("Halka")]
    [InlineData("role; DROP DATABASE postgres")]
    [InlineData("role\"quoted")]
    [InlineData("1role")]
    [InlineData("role name")]
    public void BootstrapSql_RejectsAnythingElse(string value) => Assert.Throws<ArgumentException>(() => BootstrapSql.Identifier(value));

    [Fact]
    public void BootstrapSql_CreatesNonPrivilegedRoles_AndEscapesPasswords()
    {
        var statements = BootstrapSql.Build("halka_migrator", "pa'ss", [new DatabaseBootstrap("halka_iam", "halka_iam_app", "run'time")]);

        Assert.Contains(statements, statement => statement.StartsWith("CREATE ROLE halka_migrator LOGIN PASSWORD 'pa''ss' NOSUPERUSER NOCREATEDB NOCREATEROLE", StringComparison.Ordinal));
        Assert.Contains(statements, statement => statement.StartsWith("CREATE ROLE halka_iam_app LOGIN PASSWORD 'run''time' NOSUPERUSER", StringComparison.Ordinal));
        Assert.Contains("CREATE DATABASE halka_iam OWNER halka_migrator", statements);
        Assert.Contains("REVOKE ALL ON DATABASE halka_iam FROM PUBLIC", statements);
        Assert.DoesNotContain(statements, statement => statement.Contains(" SUPERUSER", StringComparison.Ordinal) && !statement.Contains("NOSUPERUSER", StringComparison.Ordinal));
    }

    [Fact]
    public void RuntimeGrants_NeverIncludeDdlOrAuditMutation()
    {
        var grants = MigratorRunner.IamRuntimeGrants("halka_iam_app");

        Assert.DoesNotContain(grants, statement => statement.StartsWith("GRANT", StringComparison.Ordinal)
            && (statement.Contains("CREATE", StringComparison.Ordinal) || statement.Contains("TRUNCATE", StringComparison.Ordinal) || statement.Contains("ALL PRIVILEGES", StringComparison.Ordinal)));
        Assert.Contains(grants, statement => statement.StartsWith("REVOKE UPDATE, DELETE, TRUNCATE", StringComparison.Ordinal) && statement.Contains("audit_events", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => MigratorRunner.IamRuntimeGrants("app; DROP TABLE users"));
    }

    [Fact]
    public void OneTimeToken_Hash_IsSha256AndDeterministic()
    {
        var first = OneTimeTokenService.Hash("token-value");

        Assert.Equal(32, first.Length);
        Assert.Equal(first, OneTimeTokenService.Hash("token-value"));
        Assert.NotEqual(first, OneTimeTokenService.Hash("token-valuE"));
    }

    [Fact]
    public async Task LocalhostLoopbackHandler_RoutesToLoopback_ButKeepsTheHostForTlsAndRouting()
    {
        var inner = new RecordingHandler();
        using var client = new HttpClient(new LocalhostLoopbackHandler { InnerHandler = inner });

        await client.GetAsync("https://id.halka.localhost:9443/.well-known/openid-configuration?x=1");
        await client.GetAsync("https://example.org/path");

        Assert.Equal("https://127.0.0.1:9443/.well-known/openid-configuration?x=1", inner.Requests[0].Uri);
        Assert.Equal("id.halka.localhost:9443", inner.Requests[0].Host);
        Assert.Equal("https://example.org/path", inner.Requests[1].Uri);
        Assert.Null(inner.Requests[1].Host);
    }

    [Fact]
    public void DatabaseSettings_ReadsThePasswordFromAFile_AndQuotesValues()
    {
        var directory = Directory.CreateTempSubdirectory("halka-unit-");
        try
        {
            var passwordFile = Path.Combine(directory.FullName, "db-password");
            File.WriteAllText(passwordFile, "p;w=d value\n");
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Database:Host"] = "postgres",
                ["Database:Name"] = "halka_iam",
                ["Database:Username"] = "halka_iam_app",
                ["Database:PasswordFile"] = passwordFile,
            }).Build();

            var connectionString = DatabaseSettings.BuildConnectionString(configuration.GetSection("Database"));

            var parsed = new System.Data.Common.DbConnectionStringBuilder { ConnectionString = connectionString };
            Assert.Equal("p;w=d value", parsed["Password"]);
            Assert.Equal("postgres", parsed["Host"]);
            Assert.Equal("halka_iam", parsed["Database"]);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void SecretFile_MissingOrEmpty_FailsClosed()
    {
        var directory = Directory.CreateTempSubdirectory("halka-unit-");
        try
        {
            var empty = Path.Combine(directory.FullName, "empty");
            File.WriteAllText(empty, "  \n");

            Assert.Throws<InvalidOperationException>(() => SecretFile.Read(Path.Combine(directory.FullName, "missing")));
            Assert.Throws<InvalidOperationException>(() => SecretFile.Read(empty));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void DevPki_ServerCertificate_ChainsToTheAuthority_AndIsLimitedToServerAuthentication()
    {
        using var authority = DevPki.CreateAuthority("Unit Test CA", DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(2));
        using var leaf = DevPki.CreateServerCertificate(authority, ["id.halka.localhost"], DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(1));
        using var other = DevPki.CreateAuthority("Other CA", DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(2));

        Assert.True(Chains(leaf, authority));
        Assert.False(Chains(leaf, other));
        Assert.True(leaf.MatchesHostname("id.halka.localhost"));
        Assert.False(leaf.MatchesHostname("pano.localhost"));
        Assert.False(leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
        Assert.Equal(["1.3.6.1.5.5.7.3.1"], leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Select(oid => oid.Value));
        Assert.NotEqual(DevPki.SpkiHash(leaf), DevPki.SpkiHash(authority));

        static bool Chains(X509Certificate2 certificate, X509Certificate2 root)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(certificate);
        }
    }

    [Fact]
    public void LocalInit_IsIdempotent_AndSeparatesKeyRoles()
    {
        var directory = Directory.CreateTempSubdirectory("halka-unit-");
        try
        {
            var target = Path.Combine(directory.FullName, ".local");
            LocalInitializer.Initialize(target, []);
            var before = Snapshot(target);

            var secondRunLog = new List<string>();
            LocalInitializer.Initialize(target, secondRunLog);

            Assert.Empty(secondRunLog);
            Assert.Equal(before.Where(pair => !pair.Key.EndsWith("manifest.json", StringComparison.Ordinal)), Snapshot(target).Where(pair => !pair.Key.EndsWith("manifest.json", StringComparison.Ordinal)));

            // TLS, Data Protection wrapping and seed material are distinct artefacts; the bootstrap script has no superuser grant.
            Assert.True(File.Exists(Path.Combine(target, "tls", "iam.key")));
            Assert.True(File.Exists(Path.Combine(target, "dp-wrap", "iam.pfx")));
            Assert.True(File.Exists(Path.Combine(target, "seed", "credentials.json")));
            var bootstrap = File.ReadAllText(Path.Combine(target, "postgres", "init", "01-bootstrap.sql"));
            Assert.Contains("CREATE DATABASE halka_iam OWNER halka_migrator", bootstrap);
            Assert.DoesNotContain(" SUPERUSER", bootstrap.Replace("NOSUPERUSER", string.Empty, StringComparison.Ordinal));
            var manifest = File.ReadAllText(Path.Combine(target, "manifest.json"));
            Assert.DoesNotContain(File.ReadAllText(Path.Combine(target, "secrets", "db-iam")).Trim(), manifest);

            var seed = SeedData.Load(Path.Combine(target, "seed", "credentials.json"));
            Assert.Equal(4, seed.Users.Count);
            Assert.Equal(4, seed.Users.Select(user => user.Password).Distinct().Count());
            Assert.All(seed.Users, user => Assert.Matches("^hk(-[A-HJ-NP-Z2-9]{6}){4}$", user.Password));
        }
        finally
        {
            directory.Delete(recursive: true);
        }

        static Dictionary<string, string> Snapshot(string root)
            => Directory.GetFiles(root, "*", SearchOption.AllDirectories)
                .ToDictionary(path => Path.GetRelativePath(root, path), path => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))));
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<(string Uri, string? Host)> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.RequestUri!.ToString(), request.Headers.Host));
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }
}
