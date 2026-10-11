using Halka.Iam.Identity;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;

namespace Halka.Iam.Admin;

public static class AuthorizationPolicies
{
    /// <summary>Any administrative role. Roles come from the database on every request, never from the cookie.</summary>
    public const string AdminArea = "AdminArea";
    public const string SecurityAdmin = "SecurityAdmin";
    public const string ApplicationAdmin = "ApplicationAdmin";
    public const string PlatformAdmin = "PlatformAdmin";

    public static IServiceCollection AddHalkaAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(AdminArea, policy => policy
                .AddAuthenticationSchemes(SessionDefaults.Scheme)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.Administrative))
            .AddPolicy(SecurityAdmin, policy => policy
                .AddAuthenticationSchemes(SessionDefaults.Scheme)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.SecurityAdmin, Roles.PlatformAdmin))
            .AddPolicy(ApplicationAdmin, policy => policy
                .AddAuthenticationSchemes(SessionDefaults.Scheme)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.ApplicationAdmin, Roles.PlatformAdmin))
            .AddPolicy(PlatformAdmin, policy => policy
                .AddAuthenticationSchemes(SessionDefaults.Scheme)
                .RequireAuthenticatedUser()
                .RequireRole(Roles.PlatformAdmin));
        return services;
    }
}
