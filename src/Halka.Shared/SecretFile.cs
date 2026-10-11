using Microsoft.Extensions.Configuration;

namespace Halka.Shared;

/// <summary>Reads secrets that are provided as private mounted files instead of environment variables.</summary>
public static class SecretFile
{
    public static string Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"Secret file was not found: {path}");
        }

        var value = File.ReadAllText(path).Trim();
        if (value.Length == 0)
        {
            throw new InvalidOperationException($"Secret file is empty: {path}");
        }

        return value;
    }

    /// <summary>Returns the inline value when present, otherwise the content of the file referenced by "{key}File".</summary>
    public static string? Resolve(IConfiguration section, string key)
    {
        var inline = section[key];
        if (!string.IsNullOrEmpty(inline))
        {
            return inline;
        }

        var file = section[key + "File"];
        return string.IsNullOrEmpty(file) ? null : Read(file);
    }
}
