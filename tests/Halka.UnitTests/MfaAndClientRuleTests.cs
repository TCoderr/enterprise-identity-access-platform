using Halka.Iam.Clients;
using Halka.Iam.Data;
using Halka.Iam.Mfa;
using Halka.Iam.Protocol;
using OtpNet;

namespace Halka.UnitTests;

public sealed class MfaAndClientRuleTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 10, 0, 15, TimeSpan.Zero);
    private static readonly IReadOnlySet<string> KnownScopes = new HashSet<string> { "profile", "email", "workspace.read", "workspace.write" };

    [Fact]
    public void Totp_MatchesTheRfc6238Sha1TestVector()
    {
        // RFC 6238 appendix B, SHA-1, secret "12345678901234567890": at 59 seconds the 8-digit value is 94287082.
        var secret = "12345678901234567890"u8.ToArray();
        Assert.Equal("287082", TotpCodes.Compute(secret, DateTimeOffset.FromUnixTimeSeconds(59)));
        Assert.True(TotpCodes.TryVerify(secret, "287082", DateTimeOffset.FromUnixTimeSeconds(59), out var step));
        Assert.Equal(1, step);
    }

    [Fact]
    public void Totp_AcceptsOneStepOfSkewInEitherDirection_AndReportsTheMatchedStep()
    {
        var secret = TotpCodes.GenerateSecret();
        var current = Now.ToUnixTimeSeconds() / TotpCodes.StepSeconds;

        foreach (var offset in new[] { -1, 0, 1 })
        {
            var code = TotpCodes.Compute(secret, Now.AddSeconds(offset * TotpCodes.StepSeconds));
            Assert.True(TotpCodes.TryVerify(secret, code, Now, out var matched));
            Assert.Equal(current + offset, matched);
        }

        foreach (var offset in new[] { -2, 2, 10 })
        {
            Assert.False(TotpCodes.TryVerify(secret, TotpCodes.Compute(secret, Now.AddSeconds(offset * TotpCodes.StepSeconds)), Now, out _));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("abcdef")]
    public void Totp_RejectsMalformedInput(string? code)
        => Assert.False(TotpCodes.TryVerify(TotpCodes.GenerateSecret(), code, Now, out _));

    [Fact]
    public void Totp_NormalizesSpacesAndDashes_AndUsesA160BitSecret()
    {
        var secret = TotpCodes.GenerateSecret();
        var code = TotpCodes.Compute(secret, Now);

        Assert.Equal(20, secret.Length);
        Assert.True(TotpCodes.TryVerify(secret, $"{code[..3]} {code[3..]}", Now, out _));
        Assert.True(TotpCodes.TryVerify(secret, $"{code[..3]}-{code[3..]}", Now, out _));
        Assert.NotEqual(TotpCodes.ToBase32(secret), TotpCodes.ToBase32(TotpCodes.GenerateSecret()));
    }

    [Fact]
    public void ProvisioningUri_FollowsTheKeyUriFormat()
    {
        var secret = TotpCodes.GenerateSecret();

        var uri = new Uri(TotpCodes.ProvisioningUri("Halka ID", "user+tag@example.test", secret));

        Assert.Equal("otpauth", uri.Scheme);
        Assert.Equal("totp", uri.Host);
        Assert.Equal("/Halka%20ID:user%2Btag%40example.test", uri.AbsolutePath);
        Assert.Contains($"secret={Base32Encoding.ToString(secret)}", uri.Query);
        Assert.Contains("issuer=Halka%20ID", uri.Query);
        Assert.Contains("digits=6", uri.Query);
        Assert.Contains("period=30", uri.Query);
    }

    [Fact]
    public void RecoveryCodes_AreGrouped_Normalised_AndHashedPerUser()
    {
        var code = RecoveryCodes.Generate();
        var user = Guid.NewGuid();

        Assert.Matches("^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$", code);
        Assert.Equal(RecoveryCodes.Normalize(code), RecoveryCodes.Normalize(code.ToLowerInvariant().Replace('-', ' ')));
        Assert.Equal(16, RecoveryCodes.Normalize(code).Length);
        Assert.Equal(RecoveryCodes.Hash(user, RecoveryCodes.Normalize(code)), RecoveryCodes.Hash(user, RecoveryCodes.Normalize(code)));
        Assert.NotEqual(RecoveryCodes.Hash(user, RecoveryCodes.Normalize(code)), RecoveryCodes.Hash(Guid.NewGuid(), RecoveryCodes.Normalize(code)));
        Assert.Equal(1000, Enumerable.Range(0, 1000).Select(_ => RecoveryCodes.Generate()).Distinct().Count());
    }

    [Theory]
    [InlineData("https://pano.localhost:9444/signin-oidc", true)]
    [InlineData("https://127.0.0.1:9444/signin-oidc", true)]
    [InlineData("http://pano.localhost:9444/signin-oidc", false)]
    [InlineData("https://pano.localhost:9444/signin-oidc#frag", false)]
    [InlineData("https://*.pano.localhost/signin-oidc", false)]
    [InlineData("https://pano.localhost:9444/*", false)]
    [InlineData("https://user:pw@pano.localhost/signin-oidc", false)]
    [InlineData("/signin-oidc", false)]
    [InlineData("pano.localhost/signin-oidc", false)]
    [InlineData(" https://pano.localhost/signin-oidc", false)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("", false)]
    public void RedirectUri_RegistrationRules(string uri, bool valid)
        => Assert.Equal(valid, ClientRules.ValidateRegisteredUri(uri) is null);

    [Fact]
    public void WebClient_NeedsRedirectUriAndOpenId_AndOnlyKnownScopes()
    {
        var valid = new ClientRegistration("notes-web", "Notes", ClientKind.Web, ["https://notes.example/cb"], [], ["openid", "profile", "workspace.read"], "explicit");
        Assert.Empty(ClientRules.Validate(valid, KnownScopes));

        Assert.NotEmpty(ClientRules.Validate(valid with { RedirectUris = [] }, KnownScopes));
        Assert.NotEmpty(ClientRules.Validate(valid with { Scopes = ["profile"] }, KnownScopes));
        Assert.NotEmpty(ClientRules.Validate(valid with { Scopes = ["openid", "admin.everything"] }, KnownScopes));
        Assert.NotEmpty(ClientRules.Validate(valid with { ClientId = "Notes Web" }, KnownScopes));
        Assert.NotEmpty(ClientRules.Validate(valid with { ConsentType = "external" }, KnownScopes));
        Assert.NotEmpty(ClientRules.Validate(valid with { Kind = "native" }, KnownScopes));
    }

    [Fact]
    public void MachineClient_CannotHaveRedirectUrisOrIdentityScopes_AndGetsOnlyTokenPermissions()
    {
        var machine = new ClientRegistration("batch-job", "Batch", ClientKind.Machine, [], [], ["workspace.read"], "implicit");
        Assert.Empty(ClientRules.Validate(machine, KnownScopes));
        Assert.NotEmpty(ClientRules.Validate(machine with { RedirectUris = ["https://x.example/cb"] }, KnownScopes));
        foreach (var identityScope in new[] { "openid", "profile", "email", "offline_access" })
        {
            Assert.NotEmpty(ClientRules.Validate(machine with { Scopes = ["workspace.read", identityScope] }, KnownScopes));
        }

        var permissions = ClientRegistry.Describe(machine, "secret").Permissions;
        Assert.Contains("gt:client_credentials", permissions);
        Assert.Contains("scp:workspace.read", permissions);
        Assert.DoesNotContain("ept:authorization", permissions);
        Assert.DoesNotContain("gt:authorization_code", permissions);
        Assert.DoesNotContain("gt:refresh_token", permissions);
        Assert.DoesNotContain("ept:introspection", permissions);
    }

    [Fact]
    public void WebAndResourceClients_GetLeastPrivilegePermissions()
    {
        var web = ClientRegistry.Describe(new ClientRegistration("notes-web", "Notes", ClientKind.Web, ["https://notes.example/cb"], [], ["openid", "profile", "offline_access", "workspace.read"], "explicit"), "s");
        Assert.Contains("gt:authorization_code", web.Permissions);
        Assert.Contains("gt:refresh_token", web.Permissions);
        Assert.Contains("rst:code", web.Permissions);
        Assert.Contains("ft:pkce", web.Requirements);
        Assert.DoesNotContain("gt:client_credentials", web.Permissions);
        Assert.DoesNotContain("gt:password", web.Permissions);
        Assert.DoesNotContain("gt:implicit", web.Permissions);
        Assert.DoesNotContain("scp:workspace.write", web.Permissions);

        var withoutOffline = ClientRegistry.Describe(new ClientRegistration("notes-web", "Notes", ClientKind.Web, ["https://notes.example/cb"], [], ["openid"], "explicit"), "s");
        Assert.DoesNotContain("gt:refresh_token", withoutOffline.Permissions);

        var resource = ClientRegistry.Describe(new ClientRegistration("notes-api", "API", ClientKind.Resource, [], [], [], "implicit"), "s");
        Assert.Equal(["ept:introspection"], resource.Permissions);
    }

    [Fact]
    public void GeneratedClientSecret_Has256BitsOfEntropy_AndIsUnique()
    {
        var secrets = Enumerable.Range(0, 200).Select(_ => ClientRegistry.GenerateSecret()).ToList();

        Assert.Equal(200, secrets.Distinct().Count());
        Assert.All(secrets, secret => Assert.Equal(43, secret.Length));
        Assert.All(secrets, secret => Assert.Matches("^[A-Za-z0-9_-]+$", secret));
    }

    [Fact]
    public void KeyOverlap_CoversTheLongestTokenLifetimePlusSkew()
    {
        var options = new ProtocolOptions();

        Assert.Equal(options.RefreshTokenLifetime + options.KeyRetirementSkew, options.KeyOverlap);
        Assert.True(options.KeyOverlap > options.AccessTokenLifetime);
        Assert.True(options.KeyOverlap > options.IdentityTokenLifetime);
    }

    [Theory]
    [InlineData("workspace.read", true)]
    [InlineData("a", false)]
    [InlineData("openid", false)]
    [InlineData("Workspace.Read", false)]
    [InlineData("workspace read", false)]
    public void ScopeNames_AreValidated(string name, bool valid)
        => Assert.Equal(valid, ClientRules.ValidateScope(new ScopeRegistration(name, "Display", "Description", "workspace-api")).Count == 0);
}
