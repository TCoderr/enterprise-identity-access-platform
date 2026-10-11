using System.Net;
using System.Text;

namespace Halka.IntegrationTests.Stage3;

[Collection(StackCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Protocol)]
public sealed class ResourceApiTests(StackFixture fixture)
{
    private const string PanoScopes = "openid profile email offline_access workspace.read workspace.write";
    private const string RaporScopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    private static string Challenge(ProtocolResponse response) => response.Raw.Headers.WwwAuthenticate.ToString();

    [Fact]
    public async Task Api_AcceptsAValidAccessToken_ForTheScopesItCarries()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, PanoScopes);

        var created = await pano.ApiAsync(HttpMethod.Post, "/notes", tokens.AccessToken, "{\"text\":\"first note\"}");
        var listed = await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken);

        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.Equal(user.Id.ToString(), created.String("author"));
        Assert.Equal(HttpStatusCode.OK, listed.Status);
        Assert.Contains(listed.Json.EnumerateArray(), note => note.GetProperty("text").GetString() == "first note");
    }

    [Fact]
    public async Task Api_WithoutToken_OrWithGarbageOrTamperedToken_Returns401WithBearerChallenge()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, PanoScopes);
        var tampered = tokens.AccessToken[..^2] + (tokens.AccessToken.EndsWith("AA", StringComparison.Ordinal) ? "BB" : "AA");

        var none = await pano.ApiAsync(HttpMethod.Get, "/notes", bearer: null);
        var garbage = await pano.ApiAsync(HttpMethod.Get, "/notes", "this-is-not-a-token");
        var changed = await pano.ApiAsync(HttpMethod.Get, "/notes", tampered);
        var refreshAsBearer = await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.RefreshToken);

        foreach (var response in new[] { none, garbage, changed, refreshAsBearer })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
            Assert.StartsWith("Bearer", Challenge(response));
        }

        Assert.Contains("invalid_token", Challenge(garbage));
        Assert.Contains("invalid_token", Challenge(changed));
    }

    [Fact]
    public async Task Api_RejectsAnIdTokenPresentedAsBearer()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, PanoScopes);

        var response = await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.IdToken);

        Assert.True(response.Status == HttpStatusCode.Unauthorized, $"{response.Status}: {Challenge(response)}");
        Assert.Contains("invalid_token", Challenge(response));
    }

    [Fact]
    public async Task Api_RejectsATokenThatWasNotIssuedForThisAudience()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);

        // A genuine, active access token of the same user and client, but without any Workspace API scope:
        // its audience does not include the API.
        var identityOnly = await pano.SignInAsync(browser, user, "openid profile");
        Assert.Equal(HttpStatusCode.OK, (await pano.UserInfoAsync(identityOnly.AccessToken)).Status);

        var response = await pano.ApiAsync(HttpMethod.Get, "/notes", identityOnly.AccessToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
    }

    [Fact]
    public async Task Api_InsufficientScope_Returns403WithStandardChallengeAndProblemDetails()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var rapor = ProtocolClient.Rapor(Stack);
        var tokens = await rapor.SignInAsync(browser, user, RaporScopes);

        var read = await rapor.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken);
        var write = await rapor.ApiAsync(HttpMethod.Post, "/notes", tokens.AccessToken, "{\"text\":\"should not be stored\"}");
        var jobs = await rapor.ApiAsync(HttpMethod.Get, "/jobs/status", tokens.AccessToken);

        Assert.Equal(HttpStatusCode.OK, read.Status);
        Assert.Equal(HttpStatusCode.Forbidden, write.Status);
        Assert.Contains("insufficient_scope", Challenge(write));
        Assert.Contains("workspace.write", Challenge(write));
        Assert.Equal("application/problem+json", write.Raw.Content.Headers.ContentType?.MediaType);
        Assert.Equal("Insufficient scope", write.String("title"));
        Assert.Equal(HttpStatusCode.Forbidden, jobs.Status);
        Assert.DoesNotContain((await rapor.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Json.EnumerateArray(),
            note => note.GetProperty("text").GetString() == "should not be stored");
    }

    [Fact]
    public async Task Api_SensitiveEndpoint_RequiresMultiFactorSignIn_PasswordOnlySessionIsRefused()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, PanoScopes);

        var response = await pano.ApiAsync(HttpMethod.Get, "/notes/sensitive", tokens.AccessToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.Status);
        Assert.EndsWith("/step-up-required", response.String("type"));
    }

    [Fact]
    public async Task Introspection_IsOnlyAnsweredForTheAudienceOrThePresenter_AndRequiresClientAuthentication()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        using var rapor = ProtocolClient.Rapor(Stack);
        using var api = new ProtocolClient(Stack, Halka.Migrator.DemoCatalog.WorkspaceApiClientId, Stack.Demo.WorkspaceApiSecret, string.Empty);
        var tokens = await pano.SignInAsync(browser, user, PanoScopes);

        var byAudience = await api.IntrospectAsync(tokens.AccessToken);
        var byPresenter = await pano.IntrospectAsync(tokens.AccessToken);
        var byStranger = await rapor.IntrospectAsync(tokens.AccessToken);
        var anonymous = await pano.PostAsync("/connect/introspect", new Dictionary<string, string> { ["token"] = tokens.AccessToken }, null, null);
        var wrongSecret = await pano.PostAsync("/connect/introspect", new Dictionary<string, string> { ["token"] = tokens.AccessToken }, pano.ClientId, "wrong");

        Assert.True(byAudience.Json.GetProperty("active").GetBoolean());
        Assert.Equal(user.Id.ToString(), byAudience.String("sub"));
        Assert.Equal("access_token", byAudience.String("token_usage"));
        Assert.Contains("workspace.read", byAudience.String("scope"));
        Assert.True(byPresenter.Json.GetProperty("active").GetBoolean());

        // Another client learns nothing: no claims, only "inactive".
        Assert.False(byStranger.Json.GetProperty("active").GetBoolean());
        Assert.False(byStranger.Has("sub"));
        Assert.False(byStranger.Has("scope"));

        Assert.Contains(anonymous.Status, new[] { HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecret.Status);
        Assert.Equal("invalid_client", wrongSecret.Error);

        // The resource server itself cannot start user flows or obtain tokens.
        var selfToken = await api.ClientCredentialsAsync("workspace.read");
        Assert.NotEqual(HttpStatusCode.OK, selfToken.Status);
    }

    [Fact]
    public async Task Tokens_AreNeverWrittenToLogsOrAudit()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var pkce = Pkce.Create();
        var outcome = await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(PanoScopes, pkce), user);
        var tokens = await pano.ExchangeCodeAsync(outcome.Code!, pkce.Verifier);
        await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken);
        await pano.RefreshAsync(tokens.RefreshToken);

        var secrets = new[] { outcome.Code!, tokens.AccessToken, tokens.RefreshToken, tokens.IdToken, pkce.Verifier, pano.ClientSecret, user.Password };
        var logs = new StringBuilder();
        foreach (var line in Stack.Logs.Lines)
        {
            logs.AppendLine(line);
        }

        var text = logs.ToString();
        Assert.All(secrets, secret => Assert.DoesNotContain(secret, text));
    }
}
