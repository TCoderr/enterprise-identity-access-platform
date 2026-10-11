using System.Security.Cryptography.X509Certificates;
using Halka.LocalInit;

namespace Halka.TestKit;

/// <summary>In-memory test CA and server certificates. Private keys never leave the test process.</summary>
public sealed class TestPki : IDisposable
{
    private readonly X509Certificate2 _authorityWithKey;
    private readonly Dictionary<string, X509Certificate2> _issued = new(StringComparer.Ordinal);

    public TestPki(string directory)
    {
        _authorityWithKey = DevPki.CreateAuthority("Halka Test CA", DateTimeOffset.UtcNow.AddDays(-1), TimeSpan.FromDays(30));
        Authority = X509CertificateLoader.LoadCertificate(_authorityWithKey.Export(X509ContentType.Cert));
        Directory.CreateDirectory(directory);
        AuthorityPemPath = Path.Combine(directory, "test-ca.crt");
        File.WriteAllText(AuthorityPemPath, Authority.ExportCertificatePem());
    }

    /// <summary>Public certificate of the test CA (no private key).</summary>
    public X509Certificate2 Authority { get; }

    public string AuthorityPemPath { get; }

    /// <summary>SubjectPublicKeyInfo pins of the CA and of every server certificate, for the real browser.</summary>
    public IEnumerable<string> SpkiHashes => _issued.Values.Select(DevPki.SpkiHash).Append(DevPki.SpkiHash(Authority));

    /// <summary>Issues (once per host) a server certificate usable by Kestrel on every platform.</summary>
    public X509Certificate2 IssueServerCertificate(string host)
    {
        if (_issued.TryGetValue(host, out var existing))
        {
            return existing;
        }

        using var ephemeral = DevPki.CreateServerCertificate(_authorityWithKey, [host], DateTimeOffset.UtcNow.AddDays(-1), TimeSpan.FromDays(20));

        // SslStream on Windows cannot use ephemeral keys; a PKCS#12 round trip gives the key a usable provider.
        var certificate = X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
        _issued[host] = certificate;
        return certificate;
    }

    public void Dispose()
    {
        foreach (var certificate in _issued.Values)
        {
            certificate.Dispose();
        }

        Authority.Dispose();
        _authorityWithKey.Dispose();
    }
}
