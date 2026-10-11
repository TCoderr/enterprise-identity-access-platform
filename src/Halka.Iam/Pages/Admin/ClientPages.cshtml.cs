using Halka.Iam.Admin;
using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Mail;
using Halka.Iam.Mfa;
using Halka.Iam.Protocol;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Iam.Pages.Admin;

public sealed record ClientRow(string ClientId, string DisplayName, string Kind, bool IsDisabled, DateTimeOffset CreatedAt);

[Authorize(Policy = AuthorizationPolicies.ApplicationAdmin)]
public sealed class ClientsModel(IamDbContext db) : PageModel
{
    public IReadOnlyList<ClientRow> Clients { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken cancellationToken)
        => Clients = await (
            from application in db.Applications.AsNoTracking()
            join settings in db.ClientSettings.AsNoTracking() on application.Id equals settings.ApplicationId
            orderby application.ClientId
            select new ClientRow(application.ClientId!, application.DisplayName ?? application.ClientId!, settings.Kind, settings.IsDisabled, settings.CreatedAt))
            .ToListAsync(cancellationToken);
}

/// <summary>Form fields of a client registration. Only these fields are bound; identifiers and kind are fixed after creation.</summary>
public sealed class ClientForm
{
    public string ClientId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Kind { get; set; } = ClientKind.Web;

    public string? RedirectUris { get; set; }

    public string? PostLogoutRedirectUris { get; set; }

    public List<string> Scopes { get; set; } = [];

    public string ConsentType { get; set; } = ConsentTypes.Explicit;

    public ClientRegistration ToRegistration()
        => new(ClientId.Trim(), DisplayName.Trim(), Kind, Lines(RedirectUris), Lines(PostLogoutRedirectUris), Scopes.Distinct(StringComparer.Ordinal).ToList(), ConsentType);

    private static List<string> Lines(string? value)
        => (value ?? string.Empty).Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToList();
}

public abstract class ClientFormPage(ClientRegistry registry) : PageModel
{
    [BindProperty]
    public ClientForm Form { get; set; } = new();

    public IReadOnlyList<string> AvailableScopes { get; private set; } = [];

    public IReadOnlyList<string> Errors { get; protected set; } = [];

    /// <summary>Clear-text secret of the request that just created or rotated it. It exists only in this response.</summary>
    public string? NewSecret { get; protected set; }

    protected ClientRegistry Registry { get; } = registry;

    protected async Task LoadScopesAsync(CancellationToken cancellationToken)
        => AvailableScopes = ClientRules.IdentityScopes.Union(await Registry.KnownScopesAsync(cancellationToken)).Order(StringComparer.Ordinal).ToList();
}

[Authorize(Policy = AuthorizationPolicies.ApplicationAdmin)]
public sealed class ClientNewModel(ClientRegistry registry) : ClientFormPage(registry)
{
    public Task OnGetAsync(CancellationToken cancellationToken) => LoadScopesAsync(cancellationToken);

    [RequireStepUp]
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        await LoadScopesAsync(cancellationToken);
        try
        {
            NewSecret = await Registry.CreateAsync(Form.ToRegistration(), secret: null, HttpContext.RequireCurrentSession().UserId, cancellationToken);
        }
        catch (ClientValidationException exception)
        {
            Errors = exception.Errors;
        }

        return Page();
    }
}

[Authorize(Policy = AuthorizationPolicies.ApplicationAdmin)]
public sealed class ClientDetailModel(
    ClientRegistry registry,
    IamDbContext db,
    IOpenIddictApplicationManager applications,
    IOptions<ProtocolOptions> protocol,
    TimeProvider time) : ClientFormPage(registry)
{
    [BindProperty(SupportsGet = true)]
    public string ClientId { get; set; } = string.Empty;

    public bool IsDisabled { get; private set; }

    public int ActiveGrants { get; private set; }

    public int SecretsInGrace { get; private set; }

    public int DefaultGraceMinutes => (int)protocol.Value.DefaultClientSecretGrace.TotalMinutes;

    [TempData]
    public string? Notice { get; set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
        => await LoadAsync(fillForm: true, cancellationToken) ? Page() : NotFound();

    [RequireStepUp]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken cancellationToken)
    {
        if (!await LoadAsync(fillForm: false, cancellationToken))
        {
            return NotFound();
        }

        try
        {
            // The identifier comes from the route and the kind from the database, not from the posted form.
            Form.ClientId = ClientId;
            await Registry.UpdateAsync(Form.ToRegistration(), HttpContext.RequireCurrentSession().UserId, cancellationToken);
        }
        catch (ClientValidationException exception)
        {
            Errors = exception.Errors;
            return Page();
        }

        Notice = "The registration was saved.";
        return RedirectToPage(new { ClientId });
    }

    [RequireStepUp]
    public async Task<IActionResult> OnPostDisableAsync(CancellationToken cancellationToken)
        => await SetDisabledAsync(true, "The client was disabled. Its grants and tokens were revoked and it can no longer authenticate.", cancellationToken);

    [RequireStepUp]
    public async Task<IActionResult> OnPostEnableAsync(CancellationToken cancellationToken)
        => await SetDisabledAsync(false, "The client was enabled. Tokens revoked earlier stay revoked.", cancellationToken);

    [RequireStepUp]
    public async Task<IActionResult> OnPostRotateAsync(int graceMinutes, CancellationToken cancellationToken)
    {
        if (!await LoadAsync(fillForm: true, cancellationToken))
        {
            return NotFound();
        }

        try
        {
            NewSecret = await Registry.RotateSecretAsync(ClientId, TimeSpan.FromMinutes(graceMinutes), HttpContext.RequireCurrentSession().UserId, cancellationToken);
        }
        catch (ClientValidationException exception)
        {
            Errors = exception.Errors;
        }

        await LoadAsync(fillForm: true, cancellationToken);
        return Page();
    }

    private async Task<IActionResult> SetDisabledAsync(bool disabled, string notice, CancellationToken cancellationToken)
    {
        if (!await LoadAsync(fillForm: false, cancellationToken))
        {
            return NotFound();
        }

        await Registry.SetDisabledAsync(ClientId, disabled, HttpContext.RequireCurrentSession().UserId, cancellationToken);
        Notice = notice;
        return RedirectToPage(new { ClientId });
    }

    private async Task<bool> LoadAsync(bool fillForm, CancellationToken cancellationToken)
    {
        await LoadScopesAsync(cancellationToken);
        var row = await (
            from application in db.Applications.AsNoTracking()
            join settings in db.ClientSettings.AsNoTracking() on application.Id equals settings.ApplicationId
            where application.ClientId == ClientId
            select new { application.Id, settings.Kind, settings.IsDisabled }).SingleOrDefaultAsync(cancellationToken);
        if (row is null)
        {
            return false;
        }

        IsDisabled = row.IsDisabled;
        ActiveGrants = await db.SessionGrants.CountAsync(x => x.ApplicationId == row.Id && x.RevokedAt == null, cancellationToken);
        var now = time.GetUtcNow();
        SecretsInGrace = await db.ClientSecrets.CountAsync(x => x.ApplicationId == row.Id && x.RevokedAt == null && x.NotAfter > now, cancellationToken);
        Form.Kind = row.Kind;
        Form.ClientId = ClientId;
        if (fillForm)
        {
            var application = (await applications.FindByClientIdAsync(ClientId, cancellationToken))!;
            Form.DisplayName = await applications.GetDisplayNameAsync(application, cancellationToken) ?? ClientId;
            Form.ConsentType = await applications.GetConsentTypeAsync(application, cancellationToken) ?? ConsentTypes.Explicit;
            Form.RedirectUris = string.Join('\n', await applications.GetRedirectUrisAsync(application, cancellationToken));
            Form.PostLogoutRedirectUris = string.Join('\n', await applications.GetPostLogoutRedirectUrisAsync(application, cancellationToken));
            var permissions = await applications.GetPermissionsAsync(application, cancellationToken);
            var scopes = permissions.Where(permission => permission.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal))
                .Select(permission => permission[Permissions.Prefixes.Scope.Length..]).ToList();
            if (row.Kind == ClientKind.Web)
            {
                scopes.Add(Scopes.OpenId);
                if (permissions.Contains(Permissions.GrantTypes.RefreshToken))
                {
                    scopes.Add(Scopes.OfflineAccess);
                }
            }

            Form.Scopes = scopes;
        }

        return true;
    }
}

public sealed record ScopeRow(string Name, string DisplayName, string Description, string Resources);

[Authorize(Policy = AuthorizationPolicies.ApplicationAdmin)]
public sealed class ScopesModel(ClientRegistry registry, IamDbContext db) : PageModel
{
    [BindProperty]
    public string Name { get; set; } = string.Empty;

    [BindProperty]
    public string DisplayName { get; set; } = string.Empty;

    [BindProperty]
    public string? Description { get; set; }

    [BindProperty]
    public string? Resource { get; set; }

    public IReadOnlyList<ScopeRow> Items { get; private set; } = [];

    public IReadOnlyList<string> ResourceServers { get; private set; } = [];

    public IReadOnlyList<string> Errors { get; private set; } = [];

    [TempData]
    public string? Notice { get; set; }

    public Task OnGetAsync(CancellationToken cancellationToken) => LoadAsync(cancellationToken);

    [RequireStepUp]
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        await LoadAsync(cancellationToken);
        var resource = string.IsNullOrWhiteSpace(Resource) ? null : Resource.Trim();
        if (resource is not null && !ResourceServers.Contains(resource))
        {
            Errors = ["The resource must be a registered resource server."];
            return Page();
        }

        try
        {
            await registry.CreateScopeAsync(new ScopeRegistration(Name.Trim(), DisplayName.Trim(), (Description ?? string.Empty).Trim(), resource), HttpContext.RequireCurrentSession().UserId, cancellationToken);
        }
        catch (ClientValidationException exception)
        {
            Errors = exception.Errors;
            return Page();
        }

        Notice = $"The scope {Name.Trim()} was created. Clients receive it only after it is added to their registration.";
        return RedirectToPage();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        Items = (await db.Scopes.AsNoTracking().OrderBy(x => x.Name).Select(x => new { x.Name, x.DisplayName, x.Description, x.Resources }).ToListAsync(cancellationToken))
            .Select(x => new ScopeRow(x.Name!, x.DisplayName ?? x.Name!, x.Description ?? string.Empty, string.Join(", ", System.Text.Json.JsonSerializer.Deserialize<string[]>(x.Resources ?? "[]") ?? [])))
            .ToList();
        ResourceServers = await (
            from application in db.Applications.AsNoTracking()
            join settings in db.ClientSettings.AsNoTracking() on application.Id equals settings.ApplicationId
            where settings.Kind == ClientKind.Resource
            orderby application.ClientId
            select application.ClientId!).ToListAsync(cancellationToken);
    }
}

public sealed record KeyRow(Guid Id, string Use, string Kid, string Status, DateTimeOffset CreatedAt, DateTimeOffset? RetiringSince, DateTimeOffset? RetireNotBefore, DateTimeOffset? EndedAt, bool CanRetire);

/// <summary>
/// Signing and encryption key lifecycle. PlatformAdmin only, every action needs a recent step-up and is audited.
/// Only public identifiers are shown; private key material never leaves the key service.
/// </summary>
[Authorize(Policy = AuthorizationPolicies.PlatformAdmin)]
public sealed class KeysModel(IamDbContext db, ProtocolKeyService keys, IOptions<ProtocolOptions> protocol, TimeProvider time) : PageModel
{
    public const string EmergencyConfirmation = "REVOKE";

    public IReadOnlyList<KeyRow> Items { get; private set; } = [];

    public TimeSpan Overlap => protocol.Value.KeyOverlap;

    [TempData]
    public string? Notice { get; set; }

    [TempData]
    public string? Error { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        Items = (await db.ProtocolKeys.AsNoTracking().OrderBy(x => x.Use).ThenByDescending(x => x.CreatedAt).ToListAsync(cancellationToken))
            .Select(x => new KeyRow(x.Id, x.Use, x.Kid, x.Status, x.CreatedAt, x.RetiringSince, x.RetireNotBefore, x.RetiredAt ?? x.RevokedAt,
                x.Status == ProtocolKeyStatus.Retiring && x.RetireNotBefore is { } notBefore && now >= notBefore))
            .ToList();
    }

    [RequireStepUp]
    public async Task<IActionResult> OnPostRotateAsync(string use, CancellationToken cancellationToken)
        => await RunAsync(async actor =>
        {
            var created = await keys.RotateAsync(use, actor, cancellationToken);
            return $"A new {use} key ({created.Kid[..8]}…) is active. The previous key keeps validating existing tokens until it can be retired.";
        });

    [RequireStepUp]
    public async Task<IActionResult> OnPostRetireAsync(Guid id, CancellationToken cancellationToken)
        => await RunAsync(async actor =>
        {
            await keys.RetireAsync(id, actor, cancellationToken);
            return "The key was retired and removed.";
        });

    [RequireStepUp]
    public async Task<IActionResult> OnPostEmergencyAsync(Guid id, string? confirmation, string? reason, CancellationToken cancellationToken)
    {
        if (!string.Equals(confirmation, EmergencyConfirmation, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(reason))
        {
            Error = $"Type {EmergencyConfirmation} and give a reason to confirm the emergency revocation.";
            return RedirectToPage();
        }

        return await RunAsync(async actor =>
        {
            var grants = await keys.EmergencyRevokeAsync(id, actor, reason.Trim(), cancellationToken);
            return $"The key was revoked immediately. {grants} grant(s) and all tokens were revoked; applications must authorise again.";
        });
    }

    private async Task<IActionResult> RunAsync(Func<string, Task<string>> action)
    {
        try
        {
            Notice = await action(HttpContext.RequireCurrentSession().UserId.ToString());
        }
        catch (KeyLifecycleException exception)
        {
            Error = exception.Message;
        }

        return RedirectToPage();
    }
}

/// <summary>Operational status for administrators. Counts and states only; no message content and no secrets.</summary>
public sealed class OpsModel(IamDbContext db, ProtocolKeyRing ring, SessionService sessions, TimeProvider time, IOptions<MailOptions> mail, IWebHostEnvironment environment) : PageModel
{
    public bool DatabaseReachable { get; private set; }

    public int LoadedSigningKeys { get; private set; }

    public int LoadedEncryptionKeys { get; private set; }

    public int PendingMail { get; private set; }

    public int DeadMail { get; private set; }

    public TimeSpan? OldestPendingMailAge { get; private set; }

    public int ActiveSessions { get; private set; }

    public int ActiveGrants { get; private set; }

    public bool MailWorkerEnabled => mail.Value.WorkerEnabled;

    public string EnvironmentName => environment.EnvironmentName;

    public string Version => typeof(IamHost).Assembly.GetName().Version?.ToString(3) ?? "unknown";

    public DateTimeOffset Now { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Now = time.GetUtcNow();
        DatabaseReachable = await db.Database.CanConnectAsync(cancellationToken);
        LoadedSigningKeys = ring.Keys.Count(key => key.Use == ProtocolKeyUse.Signing);
        LoadedEncryptionKeys = ring.Keys.Count(key => key.Use == ProtocolKeyUse.Encryption);
        PendingMail = await db.OutboxMessages.CountAsync(x => x.DeliveredAt == null && x.DeadAt == null, cancellationToken);
        DeadMail = await db.OutboxMessages.CountAsync(x => x.DeadAt != null, cancellationToken);
        var oldest = await db.OutboxMessages.Where(x => x.DeliveredAt == null && x.DeadAt == null).OrderBy(x => x.CreatedAt).Select(x => (DateTimeOffset?)x.CreatedAt).FirstOrDefaultAsync(cancellationToken);
        OldestPendingMailAge = oldest is null ? null : Now - oldest;
        ActiveSessions = await sessions.Active(Now).CountAsync(cancellationToken);
        ActiveGrants = await db.SessionGrants.CountAsync(x => x.RevokedAt == null, cancellationToken);
    }
}
