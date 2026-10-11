using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;

namespace Halka.Shared;

public sealed class BackchannelOptions
{
    public const string SectionName = "Backchannel";

    /// <summary>PEM file of the local development CA. When set, only this root is trusted for server-to-server calls.</summary>
    public string? CaCertificatePath { get; set; }

    /// <summary>
    /// Connects "*.localhost" hosts to the loopback interface (RFC 6761). Needed for processes running directly on a
    /// host whose resolver does not handle localhost subdomains. Must stay disabled in containers (Docker DNS aliases).
    /// </summary>
    public bool LocalhostSubdomainsToLoopback { get; set; }

    public int TimeoutSeconds { get; set; } = 10;
}

/// <summary>Server-to-server HTTP plumbing: local CA trust and optional loopback routing of "*.localhost".</summary>
public sealed class BackchannelHttp : IDisposable
{
    private readonly X509Certificate2? _ca;

    public BackchannelHttp(BackchannelOptions options)
    {
        Options = options;
        if (!string.IsNullOrWhiteSpace(options.CaCertificatePath))
        {
            _ca = X509CertificateLoader.LoadCertificateFromFile(options.CaCertificatePath);
        }
    }

    public BackchannelOptions Options { get; }

    public TimeSpan Timeout => TimeSpan.FromSeconds(Math.Clamp(Options.TimeoutSeconds, 1, 60));

    /// <summary>Creates a standalone handler chain (for components that do not use IHttpClientFactory).</summary>
    public HttpMessageHandler CreateHandler()
    {
        var primary = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false };
        Apply(primary);
        return Options.LocalhostSubdomainsToLoopback
            ? new LocalhostLoopbackHandler { InnerHandler = primary }
            : primary;
    }

    public void Apply(HttpClientHandler handler)
    {
        if (_ca is not null)
        {
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) => Validate(certificate, errors);
        }
    }

    public void Apply(SocketsHttpHandler handler)
    {
        if (_ca is not null)
        {
            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, _, errors) => Validate(certificate as X509Certificate2, errors);
        }
    }

    private bool Validate(X509Certificate2? certificate, SslPolicyErrors errors)
    {
        if (certificate is null || _ca is null)
        {
            return false;
        }

        // A name mismatch or a missing certificate is never acceptable; only the chain is re-evaluated against the local CA.
        if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate);
    }

    public void Dispose() => _ca?.Dispose();
}

/// <summary>Routes "*.localhost" requests to 127.0.0.1 while keeping the original host for TLS (SNI, name validation) and routing.</summary>
public sealed class LocalhostLoopbackHandler : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri;
        if (uri is { IsAbsoluteUri: true } && uri.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            request.Headers.Host = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
            request.RequestUri = new UriBuilder(uri) { Host = IPAddress.Loopback.ToString() }.Uri;
        }

        return base.SendAsync(request, cancellationToken);
    }
}

public static class BackchannelServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="BackchannelHttp"/> and applies it to every IHttpClientFactory client of the process.
    /// </summary>
    public static IServiceCollection AddHalkaBackchannel(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(BackchannelOptions.SectionName).Get<BackchannelOptions>() ?? new BackchannelOptions();
        var backchannel = new BackchannelHttp(options);
        services.AddSingleton(backchannel);
        services.AddHttpClient();
        services.PostConfigureAll<HttpClientFactoryOptions>(factory =>
        {
            factory.HttpMessageHandlerBuilderActions.Add(builder =>
            {
                switch (builder.PrimaryHandler)
                {
                    case HttpClientHandler handler:
                        handler.AllowAutoRedirect = false;
                        backchannel.Apply(handler);
                        break;
                    case SocketsHttpHandler sockets:
                        sockets.AllowAutoRedirect = false;
                        backchannel.Apply(sockets);
                        break;
                }

                if (options.LocalhostSubdomainsToLoopback)
                {
                    builder.AdditionalHandlers.Add(new LocalhostLoopbackHandler());
                }
            });
        });

        return services;
    }
}
