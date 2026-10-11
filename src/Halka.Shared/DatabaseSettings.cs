using System.Data.Common;
using Microsoft.Extensions.Configuration;

namespace Halka.Shared;

/// <summary>Builds a PostgreSQL connection string from discrete settings so the password can come from a private file.</summary>
public static class DatabaseSettings
{
    public static string BuildConnectionString(IConfiguration section)
    {
        var explicitValue = section["ConnectionString"];
        if (!string.IsNullOrWhiteSpace(explicitValue))
        {
            return explicitValue;
        }

        var password = SecretFile.Resolve(section, "Password")
            ?? throw new InvalidOperationException("Database password is not configured (Password or PasswordFile).");

        var builder = new DbConnectionStringBuilder
        {
            ["Host"] = Require(section, "Host"),
            ["Port"] = section["Port"] ?? "5432",
            ["Database"] = Require(section, "Name"),
            ["Username"] = Require(section, "Username"),
            ["Password"] = password,
            ["Timeout"] = section["TimeoutSeconds"] ?? "5",
            ["Command Timeout"] = section["CommandTimeoutSeconds"] ?? "15",
            ["Application Name"] = section["ApplicationName"] ?? "halka",

            // Idle connections are closed after a minute, so a connection that died with a restarted database
            // does not wait in the pool for long.
            ["Connection Idle Lifetime"] = "60",
            ["Connection Pruning Interval"] = "10",
        };

        return builder.ConnectionString;
    }

    private static string Require(IConfiguration section, string key)
        => section[key] is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"Database setting '{key}' is not configured.");
}
