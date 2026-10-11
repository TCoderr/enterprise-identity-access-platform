using System.Net;
using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.MachineDemo;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Halka.IntegrationTests.Stage7;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class MachineClientTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private ProtocolClient Machine(string? secret = null) => new(Stack, DemoCatalog.OpsMachineClientId, secret ?? Stack.Demo.OpsMachineSecret, string.Empty);

    private ProtocolClient Api() => new(Stack, DemoCatalog.WorkspaceApiClientId, Stack.Demo.WorkspaceApiSecret, string.Empty);

    [Fact]
    public async Task Machine_ClientCredentials_YieldsAClientToken_WithoutUserClaimsIdTokenOrRefreshToken()
    {
        using var machine = Machine();
        using var api = Api();

        var token = await machine.ClientCredentialsAsync("workspace.read workspace.jobs");

        Assert.Equal(HttpStatusCode.OK, token.Status);
        Assert.False(token.Has("id_token"));
        Assert.False(token.Has("refresh_token"));
        Assert.DoesNotContain('.', token.AccessToken);

        // What the resource server learns: the subject is the client itself; there is no user and no sign-in data.
        var introspection = await api.IntrospectAsync(token.AccessToken);
        Assert.True(introspection.Json.GetProperty("active").GetBoolean());
        Assert.Equal(DemoCatalog.OpsMachineClientId, introspection.String("sub"));
        Assert.Equal(DemoCatalog.OpsMachineClientId, introspection.String("client_id"));
        foreach (var userClaim in new[] { "name", "email", "preferred_username", "amr", "auth_time" })
        {
            Assert.False(introspection.Has(userClaim), $"machine token carries user claim '{userClaim}'");
        }

        // Least privilege at the API: allowed scopes work, a user-only operation and UserInfo do not.
        Assert.Equal(HttpStatusCode.OK, (await machine.ApiAsync(HttpMethod.Get, "/jobs/status", token.AccessToken)).Status);
        Assert.Equal(HttpStatusCode.OK, (await machine.ApiAsync(HttpMethod.Get, "/notes", token.AccessToken)).Status);
        var write = await machine.ApiAsync(HttpMethod.Post, "/notes", token.AccessToken, "{\"text\":\"machine\"}");
        Assert.Equal(HttpStatusCode.Forbidden, write.Status);
        Assert.Contains("insufficient_scope", write.Raw.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.Forbidden, (await machine.ApiAsync(HttpMethod.Get, "/notes/sensitive", token.AccessToken)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.UserInfoAsync(token.AccessToken)).Status);
    }

    [Fact]
    public async Task Machine_WrongCredentials_AndScopesOutsideItsRegistration_AreRefused()
    {
        using var machine = Machine();
        using var wrong = Machine("not-the-secret");

        var badSecret = await wrong.ClientCredentialsAsync("workspace.read");
        Assert.Equal(HttpStatusCode.Unauthorized, badSecret.Status);
        Assert.Equal("invalid_client", badSecret.Error);
        Assert.Contains("Basic", badSecret.Raw.Headers.WwwAuthenticate.ToString());

        var noCredentials = await machine.PostAsync("/connect/token", new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = DemoCatalog.OpsMachineClientId }, null, null);
        Assert.Contains(noCredentials.Status, new[] { HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized });
        Assert.Contains(noCredentials.Error, new[] { "invalid_client", "invalid_request" });
        Assert.False(noCredentials.Has("access_token"));

        foreach (var scope in new[] { "workspace.write", "openid", "profile", "email", "offline_access", "workspace.read openid", "does.not.exist" })
        {
            var response = await machine.ClientCredentialsAsync(scope);
            Assert.True(response.Status == HttpStatusCode.BadRequest, $"scope '{scope}' gave {(int)response.Status}");
            Assert.Contains(response.Error, new[] { "invalid_scope", "invalid_request" });
            Assert.False(response.Has("access_token"));
        }

        // Without any API scope the token has no audience and the API refuses it.
        var bare = await machine.ClientCredentialsAsync(scope: null);
        if (bare.Status == HttpStatusCode.OK)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await machine.ApiAsync(HttpMethod.Get, "/notes", bare.AccessToken)).Status);
        }
    }

    [Fact]
    public async Task Machine_CannotStartUserFlows_AndWebClientsCannotUseClientCredentials()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, user);
        using var machine = new ProtocolClient(Stack, DemoCatalog.OpsMachineClientId, Stack.Demo.OpsMachineSecret, $"{Stack.PanoOrigin}/signin-oidc");
        using var pano = ProtocolClient.Pano(Stack);

        var authorize = await machine.AuthorizeAsync(browser, machine.AuthorizeUrl("workspace.read", Pkce.Create()));
        Assert.Null(authorize.Code);
        Assert.False(authorize.ReturnedToClient);
        Assert.Equal(HttpStatusCode.BadRequest, authorize.Page!.Status);

        var webAsMachine = await pano.ClientCredentialsAsync("workspace.read");
        Assert.Equal(HttpStatusCode.BadRequest, webAsMachine.Status);
        Assert.Equal("unauthorized_client", webAsMachine.Error);
        Assert.False(webAsMachine.Has("access_token"));
    }

    [Fact]
    public async Task Machine_Disabled_TokenRequestsFail_AndIssuedTokensStopWorking()
    {
        var clientId = $"temp-machine-{Guid.NewGuid():N}"[..28];
        var secret = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().CreateAsync(
            new ClientRegistration(clientId, "Temporary machine", ClientKind.Machine, [], [], [DemoCatalog.WorkspaceRead], OpenIddictConstants.ConsentTypes.Implicit),
            secret: null, actorId: null, CancellationToken.None));
        using var machine = new ProtocolClient(Stack, clientId, secret, string.Empty);
        var token = await machine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead);
        Assert.Equal(HttpStatusCode.OK, (await machine.ApiAsync(HttpMethod.Get, "/notes", token.AccessToken)).Status);

        await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().SetDisabledAsync(clientId, true, null, CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.ApiAsync(HttpMethod.Get, "/notes", token.AccessToken)).Status);
        var again = await machine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead);
        Assert.Equal(HttpStatusCode.Unauthorized, again.Status);
        Assert.Equal("invalid_client", again.Error);

        // Enabling restores the ability to get new tokens; the revoked one stays revoked.
        await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().SetDisabledAsync(clientId, false, null, CancellationToken.None));
        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.ApiAsync(HttpMethod.Get, "/notes", token.AccessToken)).Status);
        var fresh = await machine.ClientCredentialsAsync(DemoCatalog.WorkspaceRead);
        Assert.Equal(HttpStatusCode.OK, (await machine.ApiAsync(HttpMethod.Get, "/notes", fresh.AccessToken)).Status);
    }

    [Fact]
    public async Task MachineDemo_RunsAgainstTheStack_AndPrintsOnlyMaskedValues()
    {
        var directory = Directory.CreateTempSubdirectory("halka-machine-");
        try
        {
            var secretFile = Path.Combine(directory.FullName, "client-secret");
            await File.WriteAllTextAsync(secretFile, Stack.Demo.OpsMachineSecret);
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Machine:Authority"] = Stack.IamOrigin,
                ["Machine:ApiBaseUrl"] = Stack.ApiOrigin,
                ["Machine:ClientSecretFile"] = secretFile,
                ["Backchannel:CaCertificatePath"] = Stack.Pki.AuthorityPemPath,
                ["Backchannel:LocalhostSubdomainsToLoopback"] = "true",
            }).Build();

            var report = await MachineClient.RunAsync(configuration, CancellationToken.None);

            var output = string.Join('\n', report.Lines);
            Assert.True(report.Succeeded, output);
            Assert.Contains("id_token=none", output);
            Assert.Contains("refresh_token=none", output);
            Assert.Contains("GET /jobs/status (workspace.jobs): 200", output);
            Assert.Contains("POST /notes (not permitted for this client): 403", output);
            Assert.DoesNotContain(Stack.Demo.OpsMachineSecret, output);
            Assert.Matches(@"access token: \*{4}.{4} \(\d+ chars\)", output);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task ClientSecret_Create_IsReturnedOnce_AndOnlyItsHashIsStored()
    {
        var clientId = $"temp-once-{Guid.NewGuid():N}"[..26];
        var secret = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().CreateAsync(
            new ClientRegistration(clientId, "One time", ClientKind.Machine, [], [], [DemoCatalog.WorkspaceRead], OpenIddictConstants.ConsentTypes.Implicit),
            secret: null, actorId: null, CancellationToken.None));

        Assert.Equal(43, secret.Length);
        var stored = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Applications.AsNoTracking().SingleAsync(x => x.ClientId == clientId));
        Assert.NotEqual(secret, stored.ClientSecret);
        Assert.DoesNotContain(secret, stored.ClientSecret!);
        Assert.DoesNotContain(secret, stored.Properties ?? string.Empty);
        var audit = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents.AsNoTracking().Where(x => x.TargetId == clientId).ToListAsync());
        Assert.NotEmpty(audit);
        Assert.All(audit, entry => Assert.DoesNotContain(secret, $"{entry.Reason}|{entry.ActorId}|{entry.Action}"));

        // Invalid registrations are refused before anything is stored.
        var invalid = await Assert.ThrowsAsync<ClientValidationException>(() => Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().CreateAsync(
            new ClientRegistration("Bad Id", "x", ClientKind.Web, ["http://insecure.example/cb", "https://ok.example/*"], [], ["openid", "nope"], OpenIddictConstants.ConsentTypes.Explicit),
            secret: null, actorId: null, CancellationToken.None)));
        Assert.True(invalid.Errors.Count >= 4);
        await Assert.ThrowsAsync<ClientValidationException>(() => Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().CreateAsync(
            new ClientRegistration(clientId, "Duplicate", ClientKind.Machine, [], [], [DemoCatalog.WorkspaceRead], OpenIddictConstants.ConsentTypes.Implicit),
            secret: null, actorId: null, CancellationToken.None)));
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class ClientSecretRotationTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private async Task<(string ClientId, string Secret)> CreateMachineAsync()
    {
        var clientId = $"temp-rotate-{Guid.NewGuid():N}"[..28];
        var secret = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().CreateAsync(
            new ClientRegistration(clientId, "Rotating machine", ClientKind.Machine, [], [], [DemoCatalog.WorkspaceRead], OpenIddictConstants.ConsentTypes.Implicit),
            secret: null, actorId: null, CancellationToken.None));
        return (clientId, secret);
    }

    private async Task<HttpStatusCode> TokenStatusAsync(string clientId, string secret)
    {
        using var client = new ProtocolClient(Stack, clientId, secret, string.Empty);
        return (await client.ClientCredentialsAsync(DemoCatalog.WorkspaceRead)).Status;
    }

    [Fact]
    public async Task ClientSecret_Rotation_OldSecretWorksOnlyDuringTheGraceWindow()
    {
        var (clientId, original) = await CreateMachineAsync();
        using var client = new ProtocolClient(Stack, clientId, original, string.Empty);
        var issuedBefore = await client.ClientCredentialsAsync(DemoCatalog.WorkspaceRead);

        var rotated = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().RotateSecretAsync(clientId, TimeSpan.FromMinutes(10), null, CancellationToken.None));

        Assert.NotEqual(original, rotated);
        Assert.Equal(HttpStatusCode.OK, await TokenStatusAsync(clientId, rotated));
        Assert.Equal(HttpStatusCode.OK, await TokenStatusAsync(clientId, original));
        Assert.Equal(HttpStatusCode.Unauthorized, await TokenStatusAsync(clientId, "some-other-secret"));

        // Tokens issued before the rotation are not affected by it.
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", issuedBefore.AccessToken)).Status);

        Stack.Time.Advance(TimeSpan.FromMinutes(9));
        Assert.Equal(HttpStatusCode.OK, await TokenStatusAsync(clientId, original));

        // The window ends: only the new secret authenticates.
        Stack.Time.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Unauthorized, await TokenStatusAsync(clientId, original));
        Assert.Equal(HttpStatusCode.OK, await TokenStatusAsync(clientId, rotated));

        var history = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ClientSecrets.AsNoTracking().Where(x => x.CreatedBy == null).ToListAsync());
        Assert.All(history, row => Assert.DoesNotContain(original, row.SecretHash));
    }

    [Fact]
    public async Task ClientSecret_RotationWithoutGrace_StopsTheOldSecretAtOnce_IncludingEarlierGraceEntries()
    {
        var (clientId, first) = await CreateMachineAsync();
        var second = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().RotateSecretAsync(clientId, TimeSpan.FromMinutes(10), null, CancellationToken.None));
        Assert.Equal(HttpStatusCode.OK, await TokenStatusAsync(clientId, first));

        // Suspected compromise: rotate again with no grace. Neither earlier secret may work any more.
        var third = await Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>().RotateSecretAsync(clientId, TimeSpan.Zero, null, CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, await TokenStatusAsync(clientId, first));
        Assert.Equal(HttpStatusCode.Unauthorized, await TokenStatusAsync(clientId, second));
        Assert.Equal(HttpStatusCode.OK, await TokenStatusAsync(clientId, third));

        await Assert.ThrowsAsync<ClientValidationException>(() => Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>()
            .RotateSecretAsync(clientId, TimeSpan.FromHours(25), null, CancellationToken.None)));
        await Assert.ThrowsAsync<ClientValidationException>(() => Stack.InIamAsync(services => services.GetRequiredService<ClientRegistry>()
            .RotateSecretAsync(clientId, TimeSpan.FromMinutes(-1), null, CancellationToken.None)));
    }
}
