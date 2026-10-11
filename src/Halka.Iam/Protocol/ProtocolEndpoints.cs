using System.Collections.Immutable;
using System.Security.Claims;
using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Ops;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Iam.Protocol;

/// <summary>
/// Token and UserInfo endpoints. OpenIddict has already validated the request (client authentication, code, PKCE
/// verifier, redirect URI, token entry) before these handlers run; they only apply the product rules and decide
/// which claims the new tokens carry. Errors are returned as standard OAuth error responses by the library.
/// </summary>
public static class ProtocolEndpoints
{
    private const string Scheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    public static void MapHalkaProtocol(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/connect/token", TokenAsync)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Token)
            .DisableAntiforgery()
            .ExcludeFromDescription();
        endpoints.MapMethods("/connect/userinfo", [HttpMethods.Get, HttpMethods.Post], UserInfoAsync)
            .AllowAnonymous()
            .DisableAntiforgery()
            .ExcludeFromDescription();
    }

    private static async Task<IResult> TokenAsync(
        HttpContext http,
        IOpenIddictApplicationManager applications,
        IOpenIddictScopeManager scopes,
        IOpenIddictTokenManager tokens,
        GrantService grants,
        RevocationService revocation,
        UserManager<ApplicationUser> users,
        IamDbContext db,
        IamMetrics metrics,
        CancellationToken cancellationToken)
    {
        var request = http.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var grantType = request.GrantType switch
        {
            GrantTypes.AuthorizationCode => "authorization_code",
            GrantTypes.RefreshToken => "refresh_token",
            GrantTypes.ClientCredentials => "client_credentials",
            _ => "other",
        };
        var result = await HandleTokenAsync(http, request, applications, scopes, tokens, grants, revocation, users, db, cancellationToken);
        metrics.Token(grantType, ReferenceEquals(result, Results.Empty) ? "issued" : "rejected");
        return result;
    }

    private static async Task<IResult> HandleTokenAsync(
        HttpContext http,
        OpenIddictRequest request,
        IOpenIddictApplicationManager applications,
        IOpenIddictScopeManager scopes,
        IOpenIddictTokenManager tokens,
        GrantService grants,
        RevocationService revocation,
        UserManager<ApplicationUser> users,
        IamDbContext db,
        CancellationToken cancellationToken)
    {
        if (request.IsClientCredentialsGrantType())
        {
            var application = await applications.FindByClientIdAsync(request.ClientId!, cancellationToken)
                              ?? throw new InvalidOperationException("The authenticated client cannot be found.");
            var applicationId = Guid.Parse((await applications.GetIdAsync(application, cancellationToken))!);
            var settings = await db.ClientSettings.AsNoTracking()
                .Where(x => x.ApplicationId == applicationId)
                .Select(x => new { x.Kind, x.IsDisabled })
                .SingleOrDefaultAsync(cancellationToken);
            if (settings is null || settings.IsDisabled || settings.Kind != ClientKind.Machine)
            {
                return Forbid(Errors.UnauthorizedClient, "This client is not allowed to use the client credentials grant.");
            }

            // A machine acts as itself: identity scopes, user claims, ID tokens and refresh tokens are never issued.
            var requested = request.GetScopes();
            if (requested.Any(scope => scope is Scopes.OpenId or Scopes.Profile or Scopes.Email or Scopes.OfflineAccess))
            {
                return Forbid(Errors.InvalidScope, "Identity scopes cannot be requested with the client credentials grant.");
            }

            var identity = TokenIdentity.ForClient(request.ClientId!, requested, await ResourcesAsync(scopes, requested, cancellationToken));
            return await IssueAsync(http, identity, Errors.InvalidClient);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            var principal = (await http.AuthenticateAsync(Scheme)).Principal;
            var authorizationId = principal?.GetAuthorizationId();
            if (principal is null || string.IsNullOrEmpty(authorizationId))
            {
                return Forbid(Errors.InvalidGrant, "The grant is not valid.");
            }

            // The database decides: grant not revoked, central session alive, user and client enabled.
            var state = await grants.InspectAsync(authorizationId, cancellationToken);
            if (!state.IsValid)
            {
                return Forbid(Errors.InvalidGrant, "The grant is no longer valid.");
            }

            if (request.IsRefreshTokenGrantType())
            {
                // Atomic rotation guard. Of several requests that present the same refresh token at the same time
                // exactly one can mark it redeemed; every other one is a reuse and revokes the whole grant.
                var entry = principal.GetTokenId() is { Length: > 0 } tokenId ? await tokens.FindByIdAsync(tokenId, cancellationToken) : null;
                if (entry is null || !await tokens.TryRedeemAsync(entry, cancellationToken))
                {
                    await revocation.RevokeGrantAsync(Guid.Parse(authorizationId), RevocationReason.RefreshReuse, AuditActor.Client, request.ClientId, cancellationToken);
                    return Forbid(Errors.InvalidGrant, "The refresh token has already been used.");
                }

                await grants.TouchSessionAsync(state.SessionId, cancellationToken);
            }

            var user = await users.FindByIdAsync(state.UserId.ToString());
            if (user is null)
            {
                return Forbid(Errors.InvalidGrant, "The grant is no longer valid.");
            }

            var granted = principal.GetScopes();
            var identity = TokenIdentity.ForUser(user, state.AuthTime, Amr.Split(state.Amr), granted, await ResourcesAsync(scopes, granted, cancellationToken));
            identity.SetAuthorizationId(authorizationId);
            return await IssueAsync(http, identity, Errors.InvalidGrant);
        }

        return Forbid(Errors.UnsupportedGrantType, "The grant type is not supported.");
    }

    /// <summary>
    /// Lets OpenIddict create and return the tokens. Token entries are written with optimistic concurrency; when
    /// a revocation (reuse detection, logout, client disable) touches the same grant while the tokens are being
    /// written, the library reports a concurrency conflict. The request then ends with a standard OAuth error and
    /// no token is handed out.
    /// </summary>
    private static async Task<IResult> IssueAsync(HttpContext http, ClaimsIdentity identity, string conflictError)
    {
        try
        {
            await http.SignInAsync(Scheme, new ClaimsPrincipal(identity));
            return Results.Empty;
        }
        catch (OpenIddictExceptions.ConcurrencyException) when (!http.Response.HasStarted)
        {
            return Forbid(conflictError, "The request conflicted with a concurrent revocation.");
        }
    }

    private static async Task<IResult> UserInfoAsync(
        HttpContext http,
        GrantService grants,
        UserManager<ApplicationUser> users,
        CancellationToken cancellationToken)
    {
        var principal = (await http.AuthenticateAsync(Scheme)).Principal;
        if (principal is null)
        {
            return Results.Challenge(properties: null, [Scheme]);
        }

        var state = await grants.InspectAsync(principal.GetAuthorizationId(), cancellationToken);
        var user = state.IsValid ? await users.FindByIdAsync(state.UserId.ToString()) : null;
        if (user is null)
        {
            return Results.Challenge(Properties(Errors.InvalidToken, "The access token is no longer valid."), [Scheme]);
        }

        // Claim minimisation: only what the scopes of this access token allow.
        var claims = new Dictionary<string, object>(StringComparer.Ordinal) { [Claims.Subject] = user.Id.ToString() };
        if (principal.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.DisplayName.Length > 0 ? user.DisplayName : user.Email!;
            claims[Claims.PreferredUsername] = user.Email!;
        }

        if (principal.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email!;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        return Results.Ok(claims);
    }

    private static async Task<List<string>> ResourcesAsync(IOpenIddictScopeManager scopes, ImmutableArray<string> names, CancellationToken cancellationToken)
    {
        var resources = new List<string>();
        await foreach (var resource in scopes.ListResourcesAsync(names, cancellationToken))
        {
            resources.Add(resource);
        }

        return resources;
    }

    internal static AuthenticationProperties Properties(string error, string description)
        => new(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        });

    private static IResult Forbid(string error, string description) => Results.Forbid(Properties(error, description), [Scheme]);
}
