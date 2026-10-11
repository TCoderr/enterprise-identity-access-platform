using System.Net;
using System.Text.Json;
using Halka.Iam.Data;
using Halka.Iam.Protocol;
using Halka.Iam.Revocation;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Halka.IntegrationTests.Stage7;

public sealed class KeyFixture : StackFixture;

[CollectionDefinition(Name)]
public sealed class KeyCollection : ICollectionFixture<KeyFixture>
{
    public const string Name = "keys";
}

internal static class KeyTestHelpers
{
    public const string Scopes = "openid profile offline_access workspace.read";

    public static async Task<List<JsonElement>> JwksAsync(HalkaStack stack)
    {
        using var browser = stack.NewBrowser();
        var body = (await browser.GetAsync($"{stack.IamOrigin}/.well-known/jwks")).Body;
        return JsonDocument.Parse(body).RootElement.GetProperty("keys").EnumerateArray().Select(key => key.Clone()).ToList();
    }

    public static async Task<bool> ValidatesAgainstJwksAsync(HalkaStack stack, string idToken, string audience)
    {
        using var browser = stack.NewBrowser();
        var jwks = new JsonWebKeySet((await browser.GetAsync($"{stack.IamOrigin}/.well-known/jwks")).Body);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = $"{stack.IamOrigin}/",
            ValidAudience = audience,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateLifetime = false,
        });
        return result.IsValid;
    }

    public static Task<List<ProtocolKey>> KeysAsync(HalkaStack stack, string use)
        => stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().ProtocolKeys.AsNoTracking().Where(x => x.Use == use).OrderBy(x => x.CreatedAt).ToListAsync());

    public static Task<ProtocolKey> RotateAsync(HalkaStack stack, string use)
        => stack.InIamAsync(services => services.GetRequiredService<ProtocolKeyService>().RotateAsync(use, null, CancellationToken.None));
}

[Collection(KeyCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class KeyRotationTests(KeyFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Keys_SigningRotation_NewTokensUseTheNewKey_OldTokensStayValid_ClientsFollow_AndStateSurvivesARestart()
    {
        // Before: one user signed in through the real client (its JWKS cache now holds the first key).
        var early = await Stack.CreateUserAsync();
        using var earlyBrowser = Stack.NewBrowser();
        Assert.Equal("/workspace", (await ClientFlow.SignInAsync(Stack, earlyBrowser, Stack.PanoOrigin, early)).Url.AbsolutePath);

        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var before = await client.SignInAsync(browser, user, KeyTestHelpers.Scopes);
        var oldKid = new JsonWebToken(before.IdToken).Kid;
        var publishedBefore = (await KeyTestHelpers.JwksAsync(Stack)).Select(key => key.GetProperty("kid").GetString()).ToList();
        Assert.Contains(oldKid, publishedBefore);
        Assert.Equal(oldKid, (await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing)).Single(key => key.Status == ProtocolKeyStatus.Active).Kid);

        var created = await KeyTestHelpers.RotateAsync(Stack, ProtocolKeyUse.Signing);

        // Overlap: the new public key is published next to the previous one; private parts never are.
        var jwks = await KeyTestHelpers.JwksAsync(Stack);
        Assert.Equal(publishedBefore.Append(created.Kid).Order(), jwks.Select(key => key.GetProperty("kid").GetString()).Order());
        Assert.All(jwks, key => Assert.False(key.TryGetProperty("d", out _)));

        // New tokens are signed with the new key; the token issued before still validates against the JWKS,
        // and reference tokens created before the rotation keep working at the token endpoint and the API.
        var after = await client.SignInAsync(browser, user, KeyTestHelpers.Scopes);
        Assert.Equal(created.Kid, new JsonWebToken(after.IdToken).Kid);
        Assert.True(await KeyTestHelpers.ValidatesAgainstJwksAsync(Stack, before.IdToken, "pano-web"));
        Assert.True(await KeyTestHelpers.ValidatesAgainstJwksAsync(Stack, after.IdToken, "pano-web"));
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", before.AccessToken)).Status);
        var refreshed = await client.RefreshAsync(before.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal(created.Kid, new JsonWebToken(refreshed.IdToken).Kid);

        // Database state: one active key, the previous one retiring with a retirement date after the overlap.
        var keys = await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing);
        var previous = keys.Single(key => key.Kid == oldKid);
        Assert.Equal(ProtocolKeyStatus.Retiring, previous.Status);
        Assert.Equal(ProtocolKeyStatus.Active, keys.Single(key => key.Kid == created.Kid).Status);
        Assert.Single(keys, key => key.Status == ProtocolKeyStatus.Active);
        Assert.Equal(previous.RetiringSince!.Value + new ProtocolOptions().KeyOverlap, previous.RetireNotBefore!.Value);

        // A relying party whose cached JWKS predates the rotation signs a new user in: it reloads the keys.
        var late = await Stack.CreateUserAsync();
        using var lateBrowser = Stack.NewBrowser();
        var landing = await ClientFlow.SignInAsync(Stack, lateBrowser, Stack.PanoOrigin, late);
        Assert.Equal("/workspace", landing.Url.AbsolutePath);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(landing));
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(await earlyBrowser.GetAsync($"{Stack.PanoOrigin}/")));

        // Retiring too early is refused and changes nothing.
        var refusal = await Assert.ThrowsAsync<KeyLifecycleException>(() => Stack.InIamAsync(services =>
            services.GetRequiredService<ProtocolKeyService>().RetireAsync(previous.Id, null, CancellationToken.None)));
        Assert.Contains("still protects tokens", refusal.Message);
        Assert.Equal(jwks.Count, (await KeyTestHelpers.JwksAsync(Stack)).Count);

        // Restart: the key ring is rebuilt from the database with the same identifiers and roles.
        await Stack.StopIamAsync();
        await Stack.StartIamAsync();
        var afterRestart = await KeyTestHelpers.JwksAsync(Stack);
        Assert.Equal(jwks.Select(key => key.GetProperty("kid").GetString()).Order(), afterRestart.Select(key => key.GetProperty("kid").GetString()).Order());
        var postRestart = await client.RefreshAsync(refreshed.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, postRestart.Status);
        Assert.Equal(created.Kid, new JsonWebToken(postRestart.IdToken).Kid);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", postRestart.AccessToken)).Status);
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
    }

    [Fact]
    public async Task Keys_EncryptionRotation_KeepsExistingReferenceTokensReadable()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var before = await client.SignInAsync(browser, user, KeyTestHelpers.Scopes);

        var created = await KeyTestHelpers.RotateAsync(Stack, ProtocolKeyUse.Encryption);

        // The encryption key is never published.
        Assert.DoesNotContain(await KeyTestHelpers.JwksAsync(Stack), key => key.GetProperty("kid").GetString() == created.Kid);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", before.AccessToken)).Status);
        var refreshed = await client.RefreshAsync(before.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal(HttpStatusCode.OK, (await client.ApiAsync(HttpMethod.Get, "/notes", refreshed.AccessToken)).Status);
        var keys = await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Encryption);
        Assert.Single(keys, key => key.Status == ProtocolKeyStatus.Active);
        Assert.Contains(keys, key => key.Status == ProtocolKeyStatus.Retiring);
    }

    [Fact]
    public async Task Keys_AtMostOneActiveKeyPerUse_IsEnforcedByTheDatabase_EvenForConcurrentRotations()
    {
        using var start = new ManualResetEventSlim(false);
        var rotations = Enumerable.Range(0, 4).Select(_ => Task.Run(async () =>
        {
            start.Wait();
            return await KeyTestHelpers.RotateAsync(Stack, ProtocolKeyUse.Signing);
        })).ToList();
        start.Set();
        await Task.WhenAll(rotations);

        var keys = await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing);
        Assert.Single(keys, key => key.Status == ProtocolKeyStatus.Active);
        Assert.Equal(keys.Count, keys.Select(key => key.Kid).Distinct().Count());

        // A direct insert of a second active key is rejected by the unique filtered index.
        var violation = await Assert.ThrowsAsync<DbUpdateException>(() => Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            db.ProtocolKeys.Add(new ProtocolKey
            {
                Id = Guid.NewGuid(), Use = ProtocolKeyUse.Signing, Kid = Guid.NewGuid().ToString("N"), Algorithm = "RS256",
                Status = ProtocolKeyStatus.Active, ProtectedPrivateKey = [1], CreatedAt = Stack.Time.GetUtcNow(),
            });
            await db.SaveChangesAsync();
        }));
        Assert.Contains("ux_protocol_keys_one_active_per_use", violation.InnerException!.Message);
    }
}

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class KeyRetirementTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Keys_Retire_IsOnlyPossibleAfterTheOverlap_AndThenRemovesTheKey()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var client = ProtocolClient.Pano(Stack);
        var before = await client.SignInAsync(browser, user, KeyTestHelpers.Scopes);
        var created = await KeyTestHelpers.RotateAsync(Stack, ProtocolKeyUse.Signing);
        var retiring = (await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing)).Last(key => key.Status == ProtocolKeyStatus.Retiring);

        // One minute before the end of the overlap it is still refused.
        Stack.Time.Advance(new ProtocolOptions().KeyOverlap - TimeSpan.FromMinutes(1));
        await Assert.ThrowsAsync<KeyLifecycleException>(() => Stack.InIamAsync(services =>
            services.GetRequiredService<ProtocolKeyService>().RetireAsync(retiring.Id, null, CancellationToken.None)));
        Assert.Contains(await KeyTestHelpers.JwksAsync(Stack), key => key.GetProperty("kid").GetString() == retiring.Kid);

        Stack.Time.Advance(TimeSpan.FromMinutes(2));
        await Stack.InIamAsync(services => services.GetRequiredService<ProtocolKeyService>().RetireAsync(retiring.Id, null, CancellationToken.None));

        var jwks = await KeyTestHelpers.JwksAsync(Stack);
        Assert.DoesNotContain(jwks, key => key.GetProperty("kid").GetString() == retiring.Kid);
        Assert.Contains(jwks, key => key.GetProperty("kid").GetString() == created.Kid);
        var stored = (await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing)).Single(key => key.Id == retiring.Id);
        Assert.Equal(ProtocolKeyStatus.Retired, stored.Status);
        Assert.Empty(stored.ProtectedPrivateKey);

        // Every token the retired key protected had expired by then anyway (that is what the overlap guarantees).
        Assert.Equal("invalid_grant", (await client.RefreshAsync(before.RefreshToken)).Error);

        // New sign-ins work with the remaining key. An active key cannot be "retired" directly.
        var second = await Stack.CreateUserAsync();
        using var secondBrowser = Stack.NewBrowser();
        var fresh = await client.SignInAsync(secondBrowser, second, KeyTestHelpers.Scopes);
        Assert.Equal(created.Kid, new JsonWebToken(fresh.IdToken).Kid);
        await Assert.ThrowsAsync<KeyLifecycleException>(() => Stack.InIamAsync(services =>
            services.GetRequiredService<ProtocolKeyService>().RetireAsync(created.Id, null, CancellationToken.None)));
    }

    [Fact]
    public async Task Keys_EmergencyRevoke_RemovesTheKeyImmediately_RevokesAllGrants_AndKeepsCentralSessions()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var machine = new ProtocolClient(Stack, Halka.Migrator.DemoCatalog.OpsMachineClientId, Stack.Demo.OpsMachineSecret, string.Empty);
        var tokens = await pano.SignInAsync(browser, user, KeyTestHelpers.Scopes);
        var machineToken = await machine.ClientCredentialsAsync("workspace.read");
        var compromised = (await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing)).Single(key => key.Status == ProtocolKeyStatus.Active);

        var revokedGrants = await Stack.InIamAsync(services => services.GetRequiredService<ProtocolKeyService>()
            .EmergencyRevokeAsync(compromised.Id, null, "suspected private key disclosure", CancellationToken.None));

        Assert.True(revokedGrants >= 1);

        // The key is gone from the JWKS at once (no overlap) and a replacement signs from now on.
        var jwks = await KeyTestHelpers.JwksAsync(Stack);
        Assert.DoesNotContain(jwks, key => key.GetProperty("kid").GetString() == compromised.Kid);
        var keys = await KeyTestHelpers.KeysAsync(Stack, ProtocolKeyUse.Signing);
        var stored = keys.Single(key => key.Id == compromised.Id);
        Assert.Equal(ProtocolKeyStatus.Revoked, stored.Status);
        Assert.Empty(stored.ProtectedPrivateKey);
        var replacement = Assert.Single(keys, key => key.Status == ProtocolKeyStatus.Active);
        Assert.False(await KeyTestHelpers.ValidatesAgainstJwksAsync(Stack, tokens.IdToken, "pano-web"));

        // Nothing issued under the key works any more: user tokens and machine tokens.
        Assert.Equal(HttpStatusCode.Unauthorized, (await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        Assert.Equal("invalid_grant", (await pano.RefreshAsync(tokens.RefreshToken)).Error);
        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.ApiAsync(HttpMethod.Get, "/notes", machineToken.AccessToken)).Status);
        var grant = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.AsNoTracking().SingleAsync(x => x.UserId == user.Id));
        Assert.Equal(RevocationReason.KeyCompromise, grant.RevokedReason);

        // The central session survives: the user re-authorises silently and gets tokens under the new key.
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        var again = await pano.SignInAsync(browser, user, KeyTestHelpers.Scopes);
        Assert.Equal(replacement.Kid, new JsonWebToken(again.IdToken).Kid);
        Assert.Equal(HttpStatusCode.OK, (await pano.ApiAsync(HttpMethod.Get, "/notes", again.AccessToken)).Status);
        Assert.Equal(HttpStatusCode.OK, (await machine.ClientCredentialsAsync("workspace.read")).Status);

        var audit = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents.AsNoTracking()
            .Where(x => x.Action == "key.emergency_revoked" && x.TargetId == compromised.Kid).ToListAsync());
        Assert.Single(audit);
    }
}
