using System.Text.RegularExpressions;

namespace Halka.Migrator;

public sealed record DatabaseBootstrap(string Database, string RuntimeRole, string RuntimePassword);

/// <summary>
/// Statements a PostgreSQL superuser runs once to create the migration role (owner, DDL) and, per database, a
/// restricted runtime role. Used for the local stack (initdb script) and for disposable test servers.
/// </summary>
public static partial class BootstrapSql
{
    public static IReadOnlyList<string> Build(string migratorRole, string migratorPassword, IEnumerable<DatabaseBootstrap> databases)
    {
        var statements = new List<string>
        {
            $"CREATE ROLE {Identifier(migratorRole)} LOGIN PASSWORD {Literal(migratorPassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE",
        };

        foreach (var database in databases)
        {
            statements.Add($"CREATE ROLE {Identifier(database.RuntimeRole)} LOGIN PASSWORD {Literal(database.RuntimePassword)} NOSUPERUSER NOCREATEDB NOCREATEROLE");
            statements.Add($"CREATE DATABASE {Identifier(database.Database)} OWNER {Identifier(migratorRole)}");
            statements.Add($"REVOKE ALL ON DATABASE {Identifier(database.Database)} FROM PUBLIC");
            statements.Add($"GRANT CONNECT ON DATABASE {Identifier(database.Database)} TO {Identifier(database.RuntimeRole)}");
        }

        return statements;
    }

    /// <summary>Validates and returns a plain lower-case identifier; nothing else is ever interpolated into DDL.</summary>
    public static string Identifier(string value)
        => IdentifierPattern().IsMatch(value)
            ? value
            : throw new ArgumentException($"'{value}' is not a valid role or database identifier.", nameof(value));

    private static string Literal(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

    [GeneratedRegex("^[a-z_][a-z0-9_]{0,62}$")]
    private static partial Regex IdentifierPattern();
}
