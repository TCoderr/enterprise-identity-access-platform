using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.Shared;

public static class DataProtectionSetup
{
    /// <summary>
    /// Persists the Data Protection key ring to a private mounted directory and, when configured, wraps the keys
    /// at rest with a dedicated certificate. This key ring is distinct from TLS, token signing and token encryption keys.
    /// </summary>
    public static IServiceCollection AddHalkaDataProtection(this IServiceCollection services, IConfiguration configuration, string applicationName)
    {
        var section = configuration.GetSection("DataProtection");
        var builder = services.AddDataProtection().SetApplicationName(applicationName);

        var directory = section["KeyDirectory"];
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
            builder.PersistKeysToFileSystem(new DirectoryInfo(directory));
        }

        var wrapPath = section["WrapCertificatePath"];
        if (!string.IsNullOrWhiteSpace(wrapPath))
        {
            var password = SecretFile.Resolve(section, "WrapCertificatePassword");
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(wrapPath, password);
            builder.ProtectKeysWithCertificate(certificate);
        }

        return services;
    }
}
