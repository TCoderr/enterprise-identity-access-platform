using System.Diagnostics;
using System.Formats.Tar;
using System.Text;

namespace Halka.Smoke;

public sealed record ScanFinding(string Path, string Rule);

/// <summary>
/// Scans a container filesystem (tar stream) for secret material: exact secret values anywhere, and private key or
/// PKCS#12 material in application-owned locations. The scanner itself is verified with a positive canary.
/// </summary>
public static class ImageScanner
{
    private static readonly string[] ApplicationRoots = ["app/", "src/", "keys/", "run/", "home/", "root/", "tmp/", "mail-sink/"];
    private static readonly byte[] PrivateKeyMarker = Encoding.ASCII.GetBytes("PRIVATE KEY-----");

    public static async Task<IReadOnlyList<ScanFinding>> ScanImageAsync(string image, IReadOnlyDictionary<string, string> secrets)
    {
        var (createExit, containerId) = await SmokeEnvironment.DockerAsync("create", image);
        Assert.True(createExit == 0, $"docker create failed for {image}");
        containerId = containerId.Trim();
        try
        {
            var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, UseShellExecute = false };
            start.ArgumentList.Add("export");
            start.ArgumentList.Add(containerId);
            using var process = Process.Start(start)!;
            var findings = await ScanTarAsync(process.StandardOutput.BaseStream, secrets);
            await process.WaitForExitAsync();
            Assert.Equal(0, process.ExitCode);
            return findings;
        }
        finally
        {
            await SmokeEnvironment.DockerAsync("rm", "--force", containerId);
        }
    }

    public static async Task<IReadOnlyList<ScanFinding>> ScanTarAsync(Stream tar, IReadOnlyDictionary<string, string> secrets)
    {
        var needles = secrets.Where(pair => pair.Value.Length >= 12)
            .Select(pair => (Rule: $"secret-value:{pair.Key}", Bytes: Encoding.UTF8.GetBytes(pair.Value)))
            .ToList();
        var findings = new List<ScanFinding>();
        await using var reader = new TarReader(tar);
        while (await reader.GetNextEntryAsync() is { } entry)
        {
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null)
            {
                continue;
            }

            var path = entry.Name.TrimStart('.', '/');
            var applicationOwned = ApplicationRoots.Any(root => path.StartsWith(root, StringComparison.Ordinal));
            if (applicationOwned && (path.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".p12", StringComparison.OrdinalIgnoreCase)
                                     || path.EndsWith(".key", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new ScanFinding(path, "key-file-name"));
            }

            if (entry.Length is 0 or > 96 * 1024 * 1024)
            {
                continue;
            }

            using var buffer = new MemoryStream((int)entry.Length);
            await entry.DataStream.CopyToAsync(buffer);
            var content = buffer.GetBuffer().AsMemory(0, (int)buffer.Length);
            foreach (var (rule, bytes) in needles)
            {
                if (content.Span.IndexOf(bytes) >= 0)
                {
                    findings.Add(new ScanFinding(path, rule));
                }
            }

            if (applicationOwned && content.Span.IndexOf(PrivateKeyMarker) >= 0)
            {
                findings.Add(new ScanFinding(path, "pem-private-key"));
            }
        }

        return findings;
    }

    /// <summary>A tar archive that contains exactly the kinds of leaks the scanner must find.</summary>
    public static MemoryStream BuildCanary(string secretValue)
    {
        var stream = new MemoryStream();
        using (var writer = new TarWriter(stream, TarEntryFormat.Pax, leaveOpen: true))
        {
            Write(writer, "app/appsettings.Production.json", $"{{\"Database\":{{\"Password\":\"{secretValue}\"}}}}");
            Write(writer, "app/certs/server.key", "-----BEGIN PRIVATE KEY-----\nMIIcanary\n-----END PRIVATE KEY-----\n");
            Write(writer, "app/certs/signing.pfx", "binary");
            Write(writer, "usr/lib/harmless.txt", "nothing to see here");
        }

        stream.Position = 0;
        return stream;

        static void Write(TarWriter writer, string name, string content)
            => writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)) });
    }
}
