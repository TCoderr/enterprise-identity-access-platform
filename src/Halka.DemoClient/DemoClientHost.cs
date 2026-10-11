using System.Globalization;
using System.Security.Claims;
using Halka.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Halka.DemoClient;

public sealed record DemoClientDefaults(string Name, string Slug, string Theme, string Tagline, string[] Scopes, bool CanWrite);

/// <summary>
/// Composition root shared by the two demo relying parties. Each one is a separate deployable application with its
/// own origin, cookie, database and client registration; this library provides the BFF plumbing they have in common:
/// server-side OIDC code flow with PKCE, server-side token storage, refresh single flight and per-request session
/// validation against the identity provider.
/// </summary>
public static class DemoClientHost
{
    public const string CookieScheme = "App";
    public const string OidcScheme = "Oidc";
    public const string SessionClaim = "app_sid";
    public const string FreshRequestedAt = "halka.fresh_requested_at";
    public const string IdTokenHint = "halka.id_token_hint";

    public static WebApplication Build(string[] args, DemoClientDefaults defaults, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ApplicationName = $"Halka.{defaults.Name}" });
        builder.Logging.AddHalkaLogging();
        builder.Host.UseDefaultServiceProvider(options =>
        {
            options.ValidateScopes = true;
            options.ValidateOnBuild = true;
        });
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.AddServerHeader = false);

        var section = builder.Configuration.GetSection(DemoClientOptions.SectionName);
        var settings = section.Get<DemoClientOptions>() ?? new DemoClientOptions();
        var secret = SecretFile.Resolve(section, "ClientSecret") ?? throw new InvalidOperationException("Client:ClientSecret (or Client:ClientSecretFile) is not configured.");
        var scopes = settings.Scopes.Count > 0 ? settings.Scopes : [.. defaults.Scopes];

        var services = builder.Services;
        services.Configure<DemoClientOptions>(options =>
        {
            section.Bind(options);
            options.Name = defaults.Name;
            options.Slug = defaults.Slug;
            options.Theme = defaults.Theme;
            options.Tagline = defaults.Tagline;
            options.CanWrite = defaults.CanWrite;
            options.Scopes = [.. scopes];
        });
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }

        services.AddSingleton(new ClientSecretAccessor(secret));
        services.AddHalkaDataProtection(builder.Configuration, $"Halka.{defaults.Name}");
        services.AddDbContext<ClientDbContext>(options =>
            ClientDbContext.Configure(options, DatabaseSettings.BuildConnectionString(builder.Configuration.GetSection("Database"))));
        services.AddScoped<AppSessionStore>();
        services.AddSingleton<SessionLocks>();
        services.AddSingleton<SessionValidationCache>();
        services.AddScoped<OpClient>();
        services.AddScoped<SessionGuard>();
        services.AddScoped<WorkspaceApiClient>();
        services.AddHttpClient(OpClient.HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(10));
        services.AddHttpClient(WorkspaceApiClient.HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(10));
        services.AddHalkaBackchannel(builder.Configuration);

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieScheme;
                options.DefaultChallengeScheme = OidcScheme;
            })
            .AddCookie(CookieScheme, options =>
            {
                // The cookie carries a few display claims and the identifier of the server-side session only.
                options.Cookie.Name = $"__Host-{defaults.Slug}-session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.Path = "/";
                options.Cookie.IsEssential = true;
                options.SlidingExpiration = false;
                options.ExpireTimeSpan = TimeSpan.FromHours(12);
                options.AccessDeniedPath = "/";
                options.Events.OnValidatePrincipal = ValidateSessionAsync;
            })
            .AddOpenIdConnect(OidcScheme, options =>
            {
                options.Authority = settings.Authority;
                options.ClientId = settings.ClientId;
                options.ClientSecret = secret;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.ResponseMode = OpenIdConnectResponseMode.Query;
                options.UsePkce = true;
                options.SaveTokens = false;
                options.GetClaimsFromUserInfoEndpoint = false;
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = true;
                options.CallbackPath = "/signin-oidc";
                options.SignedOutCallbackPath = "/signout-callback-oidc";
                options.SignInScheme = CookieScheme;
                options.TokenValidationParameters.NameClaimType = "name";

                // How often an on-demand reload of the provider metadata (after an unknown signing key) may happen.
                options.RefreshInterval = TimeSpan.FromSeconds(30);
                options.Scope.Clear();
                foreach (var scope in scopes)
                {
                    options.Scope.Add(scope);
                }

                options.Events.OnTokenResponseReceived = RequireSignedIdTokenAsync;
                options.Events.OnTokenValidated = PrepareSessionAsync;
                options.Events.OnTicketReceived = EstablishSessionAsync;
                options.Events.OnRemoteFailure = context =>
                {
                    // Only a fixed reason code is forwarded; provider-supplied text is never reflected.
                    var reason = context.Failure?.Message.Contains("access_denied", StringComparison.Ordinal) == true ? "denied" : "failed";
                    context.Response.Redirect($"/signin-problem?reason={reason}");
                    context.HandleResponse();
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToIdentityProviderForSignOut = context =>
                {
                    if (context.Properties.Items.TryGetValue(IdTokenHint, out var hint) && !string.IsNullOrEmpty(hint))
                    {
                        context.ProtocolMessage.IdTokenHint = hint;
                        context.Properties.Items.Remove(IdTokenHint);
                    }

                    return Task.CompletedTask;
                };
            });
        services.AddOptions<OpenIdConnectOptions>(OidcScheme)
            .Configure<BackchannelHttp>((options, backchannel) =>
            {
                options.BackchannelHttpHandler = backchannel.CreateHandler();
                options.BackchannelTimeout = backchannel.Timeout;
            });

        services.AddAuthorization();
        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = $"__Host-{defaults.Slug}-csrf";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.Path = "/";
        });
        services.Configure<CookieTempDataProviderOptions>(options =>
        {
            options.Cookie.Name = $"__Host-{defaults.Slug}-flash";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.Path = "/";
        });
        services.Configure<RouteOptions>(options => options.LowercaseUrls = true);
        services.AddRazorPages().AddApplicationPart(typeof(DemoClientHost).Assembly);
        services.AddHealthChecks().AddCheck<ClientDatabaseHealthCheck>("database");
        configure?.Invoke(builder);

        var app = builder.Build();
        app.UseHalkaSecurityHeaders();
        app.Use(FailClosedWhenSessionCannotBeVerified);
        app.UseStatusCodePagesWithReExecute("/problem", "?status={0}");
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new EmbeddedFileProvider(typeof(DemoClientHost).Assembly, "Halka.DemoClient.assets"),
            RequestPath = "/assets",
            OnPrepareResponse = context => context.Context.Response.Headers.CacheControl = "public, max-age=3600",
        });
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapRazorPages();
        app.MapHealthChecks("/health/ready").AllowAnonymous();
        return app;
    }

    public static Guid? SessionId(ClaimsPrincipal principal)
        => Guid.TryParse(principal.FindFirstValue(SessionClaim), out var id) ? id : null;

    public static StoredSession? CurrentSession(HttpContext http)
        => http.Items.TryGetValue(typeof(StoredSession), out var value) ? value as StoredSession : null;

    /// <summary>
    /// Runs on every request that carries the application cookie. The cookie alone is never enough: the
    /// server-side session must exist and the identity provider must confirm that it is still alive.
    /// </summary>
    private static async Task ValidateSessionAsync(CookieValidatePrincipalContext context)
    {
        var http = context.HttpContext;
        var session = context.Principal is { } principal && SessionId(principal) is { } id
            ? await http.RequestServices.GetRequiredService<SessionGuard>().EnsureActiveAsync(id, forceRefresh: false, http.RequestAborted)
            : null;
        if (session is null)
        {
            context.RejectPrincipal();
            await http.SignOutAsync(CookieScheme);
            return;
        }

        http.Items[typeof(StoredSession)] = session;
    }

    /// <summary>
    /// For the code flow the ASP.NET Core handler does not require a signature on the ID token it receives from the
    /// token endpoint (the specification allows relying on TLS there). This application is stricter: before the
    /// handler continues, the token library must confirm an RS256 signature made with a key from the provider's
    /// JWKS, plus issuer and audience. An unsigned ("alg": "none") or re-signed token ends the sign-in here.
    /// </summary>
    private static async Task RequireSignedIdTokenAsync(TokenResponseReceivedContext context)
    {
        var idToken = context.TokenEndpointResponse.IdToken;
        if (string.IsNullOrEmpty(idToken) || context.Options.ConfigurationManager is not { } manager)
        {
            context.Fail("The identity provider response has no ID token.");
            return;
        }

        var cancellationToken = context.HttpContext.RequestAborted;
        var configuration = await manager.GetConfigurationAsync(cancellationToken);
        string? keyId;
        try
        {
            keyId = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(idToken).Kid;
        }
        catch (Exception exception) when (exception is ArgumentException or Microsoft.IdentityModel.Tokens.SecurityTokenException)
        {
            context.Fail("The ID token is malformed.");
            return;
        }

        // After a signing key rotation the cached provider metadata does not know the new key identifier yet.
        // The metadata manager reloads in the background, so wait briefly for the reload instead of failing the
        // sign-in. The token comes from the provider over the authenticated back-channel, so a client cannot use
        // this to trigger reloads.
        if (!string.IsNullOrEmpty(keyId) && !configuration.SigningKeys.Any(key => key.KeyId == keyId))
        {
            manager.RequestRefresh();
            for (var attempt = 0; attempt < 30 && !configuration.SigningKeys.Any(key => key.KeyId == keyId); attempt++)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
                configuration = await manager.GetConfigurationAsync(cancellationToken);
            }
        }

        var parameters = context.Options.TokenValidationParameters.Clone();
        parameters.RequireSignedTokens = true;
        parameters.ValidAlgorithms = [Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256];
        parameters.ValidIssuer = configuration.Issuer;
        parameters.ValidAudience = context.Options.ClientId;
        parameters.IssuerSigningKeys = configuration.SigningKeys;
        var result = await context.Options.TokenHandler.ValidateTokenAsync(idToken, parameters);
        if (!result.IsValid)
        {
            context.Fail("The ID token was not accepted.");
        }
    }

    /// <summary>
    /// Called after the handler validated the ID token (issuer, audience, lifetime, nonce). Reduces the principal
    /// to what the UI displays and keeps the tokens aside; nothing is stored yet because the handler still has
    /// protocol checks to run (for example the access token hash).
    /// </summary>
    private static Task PrepareSessionAsync(TokenValidatedContext context)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<DemoClientOptions>>().Value;
        var time = http.RequestServices.GetRequiredService<TimeProvider>();
        var response = context.TokenEndpointResponse;
        var identity = context.Principal?.Identity as ClaimsIdentity;
        var subject = identity?.FindFirst("sub")?.Value;
        if (response is null || string.IsNullOrEmpty(response.AccessToken) || identity is null || string.IsNullOrEmpty(subject))
        {
            context.Fail("The identity provider response is incomplete.");
            return Task.CompletedTask;
        }

        // "Sign in again" was requested: the provider must report an authentication that happened after the request.
        if (context.Properties?.Items.TryGetValue(FreshRequestedAt, out var requestedAt) == true)
        {
            var authTime = long.TryParse(identity.FindFirst("auth_time")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) ? seconds : 0;
            if (!long.TryParse(requestedAt, NumberStyles.None, CultureInfo.InvariantCulture, out var requested) || authTime < requested)
            {
                context.Fail("The identity provider did not perform a fresh sign-in.");
                return Task.CompletedTask;
            }

            context.Properties.Items.Remove(FreshRequestedAt);
        }

        var expiresIn = int.TryParse(response.ExpiresIn, NumberStyles.None, CultureInfo.InvariantCulture, out var lifetime) ? lifetime : 0;
        var granted = string.IsNullOrEmpty(response.Scope) ? options.Scopes : [.. response.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];
        http.Items[typeof(TokenSet)] = new TokenSet(response.AccessToken, response.RefreshToken, response.IdToken, time.GetUtcNow().AddSeconds(expiresIn), granted);

        var minimal = new ClaimsIdentity(CookieScheme, "name", "role");
        foreach (var type in new[] { "sub", "name", "preferred_username", "email", "auth_time", "amr" })
        {
            minimal.AddClaims(identity.FindAll(type).Select(claim => new Claim(claim.Type, claim.Value)));
        }

        context.Principal = new ClaimsPrincipal(minimal);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Last step, after every protocol validation of the handler has passed: the tokens go to the server-side
    /// store and the cookie principal receives only the identifier of that session.
    /// </summary>
    private static async Task EstablishSessionAsync(TicketReceivedContext context)
    {
        var http = context.HttpContext;
        if (http.Items[typeof(TokenSet)] is not TokenSet tokens || context.Principal?.Identity is not ClaimsIdentity identity || identity.FindFirst("sub")?.Value is not { Length: > 0 } subject)
        {
            context.Fail("The sign-in could not be completed.");
            return;
        }

        var sessionId = await http.RequestServices.GetRequiredService<AppSessionStore>().CreateAsync(subject, tokens, http.RequestAborted);
        identity.AddClaim(new Claim(SessionClaim, sessionId.ToString()));
        if (context.Properties is not null)
        {
            context.Properties.IsPersistent = false;
        }
    }

    /// <summary>
    /// The application session can only be trusted after its server-side row was read and the identity provider
    /// confirmed it. When either the provider or the application's own database cannot be reached, the request
    /// ends with 503: the session is neither confirmed nor ended, no protected content is served and the cookie is
    /// kept, so the user continues without signing in again once the dependency is back.
    /// </summary>
    private static async Task FailClosedWhenSessionCannotBeVerified(HttpContext http, RequestDelegate next)
    {
        try
        {
            await next(http);
        }
        catch (Exception exception) when (!http.Response.HasStarted && (exception is AuthorizationServerUnavailableException || StoreFailures.IsUnavailable(exception)))
        {
            http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Halka.DemoClient.Availability")
                .LogError("A dependency is unavailable ({ErrorType}); the request was rejected with 503.", exception.GetType().Name);
            if (exception is not AuthorizationServerUnavailableException)
            {
                http.RequestServices.GetRequiredService<ClientDbContext>().DropIdleConnections();
            }

            var name = http.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<DemoClientOptions>>().Value;
            http.Response.Clear();
            http.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            http.Response.Headers.RetryAfter = "5";
            http.Response.Headers.CacheControl = "no-store";
            http.Response.ContentType = "text/html; charset=utf-8";
            await http.Response.WriteAsync($$"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Temporarily unavailable · {{System.Net.WebUtility.HtmlEncode(name.Name)}}</title>
                <link rel="stylesheet" href="/assets/site.css">
                </head>
                <body class="{{System.Net.WebUtility.HtmlEncode(name.Theme)}}">
                <main id="main" class="page page--medium">
                <h1>Temporarily unavailable</h1>
                <p>Your session could not be verified because the identity provider or the application's own store cannot be reached. Nothing is shown until it can be checked again. Please retry shortly.</p>
                </main>
                </body>
                </html>
                """);
        }
    }
}
