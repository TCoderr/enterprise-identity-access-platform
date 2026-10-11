using Halka.Iam.Audit;
using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Protocol;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Iam.Pages.Connect;

public sealed record ConsentScope(string Name, string DisplayName, string Description);

public sealed record ConsentView(
    string ClientId,
    string ClientName,
    string UserDisplay,
    string RedirectHost,
    IReadOnlyList<ConsentScope> Scopes,
    IReadOnlyList<KeyValuePair<string, string?>> Parameters);

/// <summary>
/// Authorization endpoint (pass-through). OpenIddict has already validated the protocol request: client, exact
/// redirect URI, response type, PKCE challenge and scope permissions. This page applies the product rules:
/// central session, forced re-authentication, consent, and creation of the grant.
/// </summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken] // Clients may POST authorization requests. Consent decisions are validated explicitly below.
public sealed class AuthorizeModel(
    IamDbContext db,
    IOpenIddictApplicationManager applications,
    IOpenIddictScopeManager scopes,
    UserManager<ApplicationUser> users,
    ClientRegistry clients,
    ConsentService consents,
    GrantService grants,
    ReauthChallenge reauth,
    AuditWriter audit,
    IAntiforgery antiforgery,
    TimeProvider time) : PageModel
{
    public const string DecisionField = "consent_decision";
    public const string Allow = "allow";
    public const string Deny = "deny";
    private const string Scheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    private static readonly Dictionary<string, (string DisplayName, string Description)> StandardScopes = new(StringComparer.Ordinal)
    {
        [Scopes.OpenId] = ("Sign you in", "Confirm who you are with a stable account identifier."),
        [Scopes.Profile] = ("Read your profile", "Your name and user name."),
        [Scopes.Email] = ("Read your e-mail address", "Your e-mail address and whether it is confirmed."),
        [Scopes.OfflineAccess] = ("Stay connected", "Keep access without asking you to sign in every few minutes, until you sign out or withdraw it."),
    };

    public ConsentView? Consent { get; private set; }

    public Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) => HandleAsync(cancellationToken);

    public Task<IActionResult> OnPostAsync(CancellationToken cancellationToken) => HandleAsync(cancellationToken);

    private async Task<IActionResult> HandleAsync(CancellationToken cancellationToken)
    {
        var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var application = await applications.FindByClientIdAsync(request.ClientId!, cancellationToken)
                          ?? throw new InvalidOperationException("The client application cannot be found.");
        var applicationId = Guid.Parse((await applications.GetIdAsync(application, cancellationToken))!);
        if (await clients.IsDisabledAsync(applicationId, cancellationToken))
        {
            return Error(Errors.UnauthorizedClient, "This application is disabled.");
        }

        // 1. Central session and freshness (prompt=login, max_age).
        var session = HttpContext.GetCurrentSession();
        var now = time.GetUtcNow();
        var forceLogin = request.HasPromptValue(PromptValues.Login) || request.MaxAge == 0;
        var needsLogin = session is null
                         || (request.MaxAge is { } maxAge && now - session.AuthTime > TimeSpan.FromSeconds(maxAge))
                         || (forceLogin && !reauth.IsSatisfied(HttpContext, request, session));
        if (needsLogin)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Error(Errors.LoginRequired, "The user must sign in.");
            }

            if (forceLogin)
            {
                reauth.Issue(HttpContext, request, session);
            }

            var returnUrl = Request.PathBase + Request.Path + QueryString.Create(RequestParameters(request));
            return Redirect($"/account/login?reauth={(session is null ? "false" : "true")}&returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        var user = await users.FindByIdAsync(session!.UserId.ToString())
                   ?? throw new InvalidOperationException("The session user cannot be found.");

        // 2. Consent.
        var requested = request.GetScopes();
        var consentType = await applications.GetConsentTypeAsync(application, cancellationToken) ?? ConsentTypes.Explicit;
        var mustAsk = consentType switch
        {
            ConsentTypes.Implicit => false,
            ConsentTypes.Systematic => true,
            _ => request.HasPromptValue(PromptValues.Consent) || !await consents.CoversAsync(user.Id, request.ClientId!, requested, cancellationToken),
        };

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if (mustAsk)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Error(Errors.ConsentRequired, "The user must consent.");
            }

            var decision = Request.HasFormContentType ? Request.Form[DecisionField].ToString() : string.Empty;
            if (decision is not (Allow or Deny))
            {
                Consent = await BuildConsentViewAsync(request, application, user, cancellationToken);
                return Page();
            }

            // A decision only counts with a valid anti-forgery token bound to this user's session.
            if (!await antiforgery.IsRequestValidAsync(HttpContext))
            {
                return BadRequest();
            }

            if (decision == Deny)
            {
                await audit.WriteAsync("consent.denied", AuditOutcome.Denied, AuditActor.User, user.Id.ToString(), "client", request.ClientId, cancellationToken: cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Error(Errors.AccessDenied, "The user denied the request.");
            }

            await consents.GrantAsync(user.Id, request.ClientId!, requested, cancellationToken);
        }

        // 3. Grant: authorization entry bound to this central session; all tokens of the flow hang off it.
        var resources = new List<string>();
        await foreach (var resource in scopes.ListResourcesAsync(requested, cancellationToken))
        {
            resources.Add(resource);
        }

        var identity = TokenIdentity.ForUser(user, session.AuthTime, session.Amr, requested, resources);
        identity.SetAuthorizationId(await grants.CreateAsync(identity, session, applicationId, request.ClientId!, requested, cancellationToken));
        await grants.TouchSessionAsync(session.Id, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return SignIn(new System.Security.Claims.ClaimsPrincipal(identity), Scheme);
    }

    private async Task<ConsentView> BuildConsentViewAsync(OpenIddictRequest request, object application, ApplicationUser user, CancellationToken cancellationToken)
    {
        var described = new List<ConsentScope>();
        foreach (var name in request.GetScopes())
        {
            if (StandardScopes.TryGetValue(name, out var standard))
            {
                described.Add(new ConsentScope(name, standard.DisplayName, standard.Description));
                continue;
            }

            var scope = await scopes.FindByNameAsync(name, cancellationToken);
            described.Add(new ConsentScope(
                name,
                (scope is null ? null : await scopes.GetDisplayNameAsync(scope, cancellationToken)) ?? name,
                (scope is null ? null : await scopes.GetDescriptionAsync(scope, cancellationToken)) ?? string.Empty));
        }

        return new ConsentView(
            request.ClientId!,
            await applications.GetDisplayNameAsync(application, cancellationToken) ?? request.ClientId!,
            $"{user.DisplayName} ({user.Email})",
            Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out var redirect) ? redirect.Authority : string.Empty,
            described,
            RequestParameters(request).ToList());
    }

    /// <summary>The protocol parameters of the request, without the fields this page adds itself.</summary>
    private static IEnumerable<KeyValuePair<string, string?>> RequestParameters(OpenIddictRequest request)
        => from parameter in request.GetParameters()
           where parameter.Key is not (DecisionField or "__RequestVerificationToken")
           let value = (string?)parameter.Value
           where value is not null
           select new KeyValuePair<string, string?>(parameter.Key, value);

    private ForbidResult Error(string error, string description)
        => Forbid(ProtocolEndpoints.Properties(error, description), Scheme);
}
