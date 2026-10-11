using Halka.Iam.Audit;
using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Halka.Iam.Protocol;

/// <summary>
/// Introspection answers from current server state, not only from the token entry: the grant, its central session
/// (including idle and absolute expiry), the user and the client must all still be valid. A rejection here is
/// turned into the standard <c>{"active": false}</c> response by OpenIddict.
/// </summary>
public sealed class ValidateIntrospectedGrantState(GrantService grants, ClientRegistry clients, IOpenIddictApplicationManager applications)
    : IOpenIddictServerHandler<ValidateIntrospectionRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
            .UseScopedHandler<ValidateIntrospectedGrantState>()
            .SetOrder(OpenIddictServerHandlers.Introspection.ValidateAuthorizedParty.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateIntrospectionRequestContext context)
    {
        var principal = context.GenericTokenPrincipal;
        if (principal is null)
        {
            return;
        }

        var authorizationId = principal.GetAuthorizationId();
        if (!string.IsNullOrEmpty(authorizationId))
        {
            var state = await grants.InspectAsync(authorizationId, context.CancellationToken);
            if (!state.IsValid)
            {
                context.Reject(error: Errors.InvalidToken, description: "The token is no longer valid.");
            }

            return;
        }

        // Tokens without a grant belong to a client alone (client_credentials).
        foreach (var presenter in principal.GetPresenters())
        {
            var application = await applications.FindByClientIdAsync(presenter, context.CancellationToken);
            var id = application is null ? null : await applications.GetIdAsync(application, context.CancellationToken);
            if (id is null || await clients.IsDisabledAsync(Guid.Parse(id), context.CancellationToken))
            {
                context.Reject(error: Errors.InvalidToken, description: "The token is no longer valid.");
                return;
            }
        }
    }
}

/// <summary>
/// Refresh token reuse detection. OpenIddict revokes the tokens of the family when a redeemed refresh token is
/// presented again; this handler runs just before that check and additionally revokes the grant itself and writes
/// an audit record, so the outcome is the same as for the concurrent case handled in the token endpoint.
/// </summary>
public sealed class RevokeGrantOnRefreshTokenReuse(IOpenIddictTokenManager tokens, RevocationService revocation)
    : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseScopedHandler<RevokeGrantOnRefreshTokenReuse>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateTokenEntry.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token
            || context.Principal is null
            || !context.Principal.HasTokenType(TokenTypeIdentifiers.RefreshToken)
            || string.IsNullOrEmpty(context.TokenId)
            || !Guid.TryParse(context.AuthorizationId, out var authorizationId))
        {
            return;
        }

        var token = await tokens.FindByIdAsync(context.TokenId, context.CancellationToken);
        if (token is not null && await tokens.HasStatusAsync(token, Statuses.Redeemed, context.CancellationToken))
        {
            await revocation.RevokeGrantAsync(authorizationId, RevocationReason.RefreshReuse, AuditActor.Client, context.Principal.GetClaim(Claims.Private.Presenter), context.CancellationToken);
        }
    }
}

/// <summary>
/// RFC 7662 section 2.2: when the caller is properly authenticated but the token is not something this server
/// introspects for it (for example an ID token), the answer is <c>{"active": false}</c>, not an OAuth error. This
/// lets a resource server tell "not a valid access token" (401) apart from "the server could not answer" (503).
/// </summary>
public sealed class NormalizeUnsupportedTokenTypeResponse : IOpenIddictServerHandler<ApplyIntrospectionResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyIntrospectionResponseContext>()
            .UseSingletonHandler<NormalizeUnsupportedTokenTypeResponse>()
            .SetOrder(OpenIddictServerHandlers.Introspection.NormalizeErrorResponse.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyIntrospectionResponseContext context)
    {
        if (string.Equals(context.Error, Errors.UnsupportedTokenType, StringComparison.Ordinal))
        {
            context.Response.Error = null;
            context.Response.ErrorDescription = null;
            context.Response.ErrorUri = null;
            context.Response[Claims.Active] = false;
        }

        return ValueTask.CompletedTask;
    }
}
