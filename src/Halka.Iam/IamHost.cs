using Halka.Iam.Admin;
using Halka.Iam.Api;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Identity;
using Halka.Iam.Mail;
using Halka.Iam.Mfa;
using Halka.Iam.Ops;
using Halka.Iam.Protocol;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Halka.Shared;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;

namespace Halka.Iam;

/// <summary>Composition root of the identity provider. Tests and the migrator reuse the same registrations.</summary>
public static class IamHost
{
    public const string TestingEnvironment = "Testing";

    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ApplicationName = typeof(IamHost).Assembly.GetName().Name,
        });

        builder.Logging.AddHalkaLogging();
        builder.Host.UseDefaultServiceProvider(options =>
        {
            options.ValidateScopes = true;
            options.ValidateOnBuild = true;
        });
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = 1024 * 1024;
        });

        AddIamCore(builder.Services, builder.Configuration);
        AddIamWeb(builder.Services, builder.Configuration, builder.Environment);
        configure?.Invoke(builder);

        var app = builder.Build();
        ConfigurePipeline(app);
        return app;
    }

    /// <summary>Data, identity and domain services. Has no dependency on the HTTP pipeline (also used by the migrator).</summary>
    public static IServiceCollection AddIamCore(IServiceCollection services, IConfiguration configuration)
    {
        services.TryAddTimeProvider();
        services.Configure<IamOptions>(configuration.GetSection(IamOptions.SectionName));
        services.Configure<CentralSessionOptions>(configuration.GetSection(CentralSessionOptions.SectionName));
        services.Configure<MailOptions>(configuration.GetSection(MailOptions.SectionName));
        services.AddOptions<IamOptions>()
            .Validate(options => Uri.TryCreate(options.PublicOrigin, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps,
                "Iam:PublicOrigin must be an absolute https URL.")
            .ValidateOnStart();

        services.AddHalkaDataProtection(configuration, "Halka.Iam");
        services.AddDbContext<IamDbContext>(options =>
            IamDbContextConfiguration.Configure(options, DatabaseSettings.BuildConnectionString(configuration.GetSection("Database"))));

        services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.Password.RequiredLength = 12;
                options.Password.RequiredUniqueChars = 5;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            })
            .AddRoles<ApplicationRole>()
            .AddEntityFrameworkStores<IamDbContext>();

        services.AddScoped<AuditWriter>();
        services.AddScoped<OneTimeTokenService>();
        services.AddScoped<MailOutbox>();
        services.AddScoped<OutboxDispatcher>();
        services.AddSingleton<IMailSink, FileMailSink>();
        services.AddScoped<SessionService>();
        services.AddScoped<RevocationService>();
        services.AddScoped<AccountService>();
        services.Configure<MfaOptions>(configuration.GetSection(MfaOptions.SectionName));
        services.AddScoped<MfaService>();
        services.AddScoped<Halka.Iam.Admin.UserAdminService>();
        services.AddMetrics();
        services.AddSingleton<IamMetrics>();
        services.Configure<RetentionOptions>(configuration.GetSection(RetentionOptions.SectionName));
        services.AddScoped<RetentionService>();
        services.AddHalkaProtocolCore(configuration);
        return services;
    }

    private static void AddIamWeb(IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        var sessions = configuration.GetSection(CentralSessionOptions.SectionName).Get<CentralSessionOptions>() ?? new CentralSessionOptions();

        services.AddHalkaRateLimiting(configuration);
        services.AddScoped<LoginService>();
        services.AddScoped<SessionSignIn>();
        services.AddScoped<SessionCookieEvents>();
        services.AddSingleton<PendingChallengeCookie>();
        services.AddHostedService<OutboxWorker>();
        services.AddHostedService<RetentionWorker>();

        services.AddAuthentication(SessionDefaults.Scheme)
            .AddCookie(SessionDefaults.Scheme, options =>
            {
                options.Cookie.Name = SessionDefaults.CookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.Path = "/";
                options.Cookie.IsEssential = true;
                options.LoginPath = "/account/login";
                options.AccessDeniedPath = "/account/access-denied";
                options.ReturnUrlParameter = "returnUrl";
                options.SlidingExpiration = false;
                options.ExpireTimeSpan = sessions.AbsoluteLifetime;
                options.EventsType = typeof(SessionCookieEvents);
            });

        services.AddHalkaAuthorization();
        services.AddHalkaProtocolServer(configuration);

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = "__Host-halka-csrf";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.Path = "/";
            options.HeaderName = "X-CSRF-TOKEN";
        });

        services.Configure<CookieTempDataProviderOptions>(options =>
        {
            options.Cookie.Name = "__Host-halka-flash";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.Path = "/";
        });
        services.Configure<RouteOptions>(options => options.LowercaseUrls = true);
        services.AddRazorPages(options =>
        {
            options.Conventions.AuthorizeFolder("/Manage");
            options.Conventions.AuthorizeFolder("/Admin", AuthorizationPolicies.AdminArea);
        }).AddMvcOptions(options => options.Filters.Add<StepUpPageFilter>());
        services.AddProblemDetails();
        services.AddExceptionHandler<UnavailableExceptionHandler>();
        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);

        if (environment.IsDevelopment() || environment.IsEnvironment(TestingEnvironment))
        {
            services.AddOpenApi();
        }
    }

    private static void ConfigurePipeline(WebApplication app)
    {
        app.UseHalkaSecurityHeaders();
        app.UseExceptionHandler("/error");
        app.UseStatusCodePagesWithReExecute("/error", "?status={0}");

        var assets = new EmbeddedFileProvider(typeof(IamHost).Assembly, "Halka.Iam.wwwroot");
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = assets,
            RequestPath = "/assets",
            OnPrepareResponse = context => context.Context.Response.Headers.CacheControl = "public, max-age=3600",
        });

        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapRazorPages();
        app.MapHalkaHealth();
        app.MapAccountApi();
        app.MapHalkaProtocol();

        if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment(TestingEnvironment))
        {
            app.MapOpenApi();
        }
    }

    private static void TryAddTimeProvider(this IServiceCollection services)
    {
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }
    }
}
