using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Iam.Protocol;

public static class ProtocolSetup
{
    /// <summary>Stores, managers and domain services of the protocol layer (no HTTP endpoints).</summary>
    public static IServiceCollection AddHalkaProtocolCore(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ProtocolOptions>(configuration.GetSection(ProtocolOptions.SectionName));
        services.AddOpenIddict().AddCore(core =>
        {
            core.UseEntityFrameworkCore().UseDbContext<IamDbContext>().ReplaceDefaultEntities<Guid>();
            core.ReplaceApplicationManager<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication<Guid>, HalkaApplicationManager>();
        });

        services.AddSingleton<ProtocolKeyRing>();
        services.AddScoped<ProtocolKeyService>();
        services.AddScoped<GrantService>();
        services.AddScoped<ConsentService>();
        services.AddScoped<ClientRegistry>();
        return services;
    }

    /// <summary>
    /// OpenIddict authorization server. Protocol mechanics (token formats, signatures, PKCE, discovery, JWKS, client
    /// authentication, standard error responses) are entirely the library's; this method only selects flows,
    /// lifetimes and endpoints and plugs in the product rules.
    /// </summary>
    public static IServiceCollection AddHalkaProtocolServer(this IServiceCollection services, IConfiguration configuration)
    {
        var iam = configuration.GetSection(IamOptions.SectionName).Get<IamOptions>() ?? new IamOptions();
        var protocol = configuration.GetSection(ProtocolOptions.SectionName).Get<ProtocolOptions>() ?? new ProtocolOptions();

        services.AddScoped<ReauthChallenge>();
        services.AddHostedService<ProtocolKeyRingInitializer>();

        services.AddOpenIddict().AddServer(server =>
        {
            if (Uri.TryCreate(iam.PublicOrigin, UriKind.Absolute, out _))
            {
                server.SetIssuer(iam.PublicOriginUri);
            }

            server.SetAuthorizationEndpointUris("connect/authorize")
                .SetTokenEndpointUris("connect/token")
                .SetUserInfoEndpointUris("connect/userinfo")
                .SetIntrospectionEndpointUris("connect/introspect")
                .SetRevocationEndpointUris("connect/revoke")
                .SetEndSessionEndpointUris("connect/endsession");

            // Only these flows exist. Implicit, hybrid, password and device flows are not enabled.
            server.AllowAuthorizationCodeFlow()
                .AllowRefreshTokenFlow()
                .AllowClientCredentialsFlow()
                .RequireProofKeyForCodeExchange();

            // Opaque reference tokens: validity is decided by server state on every use (instant revocation).
            server.UseReferenceAccessTokens().UseReferenceRefreshTokens();

            server.SetAuthorizationCodeLifetime(protocol.AuthorizationCodeLifetime)
                .SetAccessTokenLifetime(protocol.AccessTokenLifetime)
                .SetIdentityTokenLifetime(protocol.IdentityTokenLifetime)
                .SetRefreshTokenLifetime(protocol.RefreshTokenLifetime);

            // Strict rotation: a redeemed refresh token is never accepted again, not even for a short leeway.
            server.SetRefreshTokenReuseLeeway(null);

            server.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.OfflineAccess);
            server.RegisterClaims(
                Claims.Subject, Claims.Name, Claims.PreferredUsername, Claims.Email, Claims.EmailVerified,
                Claims.AuthenticationTime, Claims.AuthenticationMethodReference);

            server.Configure(options =>
            {
                // PKCE with S256 only; responses are delivered in the query string only.
                options.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain);
                options.ResponseModes.Remove(ResponseModes.Fragment);
                options.ResponseModes.Remove(ResponseModes.FormPost);
            });

            server.AddEventHandler(ValidateIntrospectedGrantState.Descriptor);
            server.AddEventHandler(RevokeGrantOnRefreshTokenReuse.Descriptor);
            server.AddEventHandler(NormalizeUnsupportedTokenTypeResponse.Descriptor);

            server.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableTokenEndpointPassthrough()
                .EnableUserInfoEndpointPassthrough()
                .EnableEndSessionEndpointPassthrough()
                .EnableStatusCodePagesIntegration();
        });

        // Registered after AddServer so the key ordering runs after OpenIddict's own post-configuration.
        services.AddSingleton<ProtocolKeyOptionsSetup>();
        services.AddSingleton<IConfigureOptions<OpenIddictServerOptions>>(provider => provider.GetRequiredService<ProtocolKeyOptionsSetup>());
        services.AddSingleton<IPostConfigureOptions<OpenIddictServerOptions>>(provider => provider.GetRequiredService<ProtocolKeyOptionsSetup>());
        services.TryAddScoped<ValidateIntrospectedGrantState>();
        services.TryAddScoped<RevokeGrantOnRefreshTokenReuse>();
        return services;
    }
}
