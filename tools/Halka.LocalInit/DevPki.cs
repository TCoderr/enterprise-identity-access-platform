using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Halka.LocalInit;

/// <summary>
/// Local development PKI built with the .NET certificate APIs: a private CA and server certificates signed by it.
/// These certificates only secure transport (TLS). They are never used for token signing, token encryption or
/// Data Protection.
/// </summary>
public static class DevPki
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    public static X509Certificate2 CreateAuthority(string commonName, DateTimeOffset notBefore, TimeSpan lifetime)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}, O=Halka ID local development", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(notBefore, notBefore + lifetime);
    }

    public static X509Certificate2 CreateServerCertificate(
        X509Certificate2 authority,
        IReadOnlyList<string> dnsNames,
        DateTimeOffset notBefore,
        TimeSpan lifetime)
    {
        if (dnsNames.Count == 0)
        {
            throw new ArgumentException("At least one DNS name is required.", nameof(dnsNames));
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={dnsNames[0]}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
        {
            names.AddDnsName(name);
        }

        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthenticationOid)], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(authority, true, false));

        var notAfter = notBefore + lifetime;
        if (notAfter > authority.NotAfter)
        {
            notAfter = authority.NotAfter;
        }

        using var issued = request.Create(authority, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));
        return issued.CopyWithPrivateKey(key);
    }

    /// <summary>Self-signed certificate used only to wrap a Data Protection key ring at rest.</summary>
    public static X509Certificate2 CreateKeyWrappingCertificate(string commonName, DateTimeOffset notBefore, TimeSpan lifetime)
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true));
        return request.CreateSelfSigned(notBefore, notBefore + lifetime);
    }

    /// <summary>Base64 SHA-256 of the SubjectPublicKeyInfo, the format Chromium expects for SPKI pinning flags.</summary>
    public static string SpkiHash(X509Certificate2 certificate)
        => Convert.ToBase64String(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));

    public static string PrivateKeyPem(X509Certificate2 certificate)
    {
        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return ecdsa.ExportPkcs8PrivateKeyPem();
        }

        using var rsa = certificate.GetRSAPrivateKey() ?? throw new InvalidOperationException("The certificate has no exportable private key.");
        return rsa.ExportPkcs8PrivateKeyPem();
    }
}
