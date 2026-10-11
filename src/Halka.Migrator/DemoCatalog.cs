using Halka.Iam.Clients;
using Halka.Iam.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.Migrator;

public sealed record DemoSeed(string PanoOrigin, string RaporOrigin, string PanoSecret, string RaporSecret, string WorkspaceApiSecret, string OpsMachineSecret);

/// <summary>
/// The demo registrations of this installation: API scopes, two web clients with different permissions, the
/// resource server and one machine client. Seeding is idempotent and never changes an existing secret.
/// </summary>
public static class DemoCatalog
{
    public const string PanoClientId = "pano-web";
    public const string RaporClientId = "rapor-web";
    public const string WorkspaceApiClientId = "workspace-api";
    public const string OpsMachineClientId = "ops-machine";

    public const string WorkspaceRead = "workspace.read";
    public const string WorkspaceWrite = "workspace.write";
    public const string WorkspaceJobs = "workspace.jobs";

    public static IReadOnlyList<ScopeRegistration> Scopes { get; } =
    [
        new(OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile, "Read your profile", "Your name and user name.", null),
        new(OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email, "Read your e-mail address", "Your e-mail address and whether it is confirmed.", null),
        new(WorkspaceRead, "Read workspace notes", "Read the notes of the demo workspace on your behalf.", WorkspaceApiClientId),
        new(WorkspaceWrite, "Add workspace notes", "Add notes to the demo workspace on your behalf.", WorkspaceApiClientId),
        new(WorkspaceJobs, "Read job status", "Read the background job status of the workspace (machine clients).", WorkspaceApiClientId),
    ];

    public static IReadOnlyList<(ClientRegistration Registration, string Secret)> Clients(DemoSeed seed) =>
    [
        (new ClientRegistration(
            PanoClientId,
            "Pano",
            ClientKind.Web,
            [$"{seed.PanoOrigin}/signin-oidc"],
            [$"{seed.PanoOrigin}/signout-callback-oidc"],
            [
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
                WorkspaceRead,
                WorkspaceWrite,
            ],
            ConsentTypes.Explicit), seed.PanoSecret),
        (new ClientRegistration(
            RaporClientId,
            "Rapor",
            ClientKind.Web,
            [$"{seed.RaporOrigin}/signin-oidc"],
            [$"{seed.RaporOrigin}/signout-callback-oidc"],
            [
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
                OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
                WorkspaceRead,
            ],
            ConsentTypes.Explicit), seed.RaporSecret),
        (new ClientRegistration(WorkspaceApiClientId, "Workspace API", ClientKind.Resource, [], [], [], ConsentTypes.Implicit), seed.WorkspaceApiSecret),
        (new ClientRegistration(OpsMachineClientId, "Operations machine client", ClientKind.Machine, [], [], [WorkspaceRead, WorkspaceJobs], ConsentTypes.Implicit), seed.OpsMachineSecret),
    ];
}
