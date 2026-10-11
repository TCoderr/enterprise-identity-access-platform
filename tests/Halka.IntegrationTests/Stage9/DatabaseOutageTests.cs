using System.Net;
using Halka.Iam.Sessions;

namespace Halka.IntegrationTests.Stage9;

/// <summary>The identity provider of this stack reaches its database through a relay that the test can interrupt.</summary>
public sealed class DatabaseOutageFixture : StackFixture
{
    protected override StackOptions Options => new() { RelayIamDatabase = true };
}

[CollectionDefinition(Name)]
public sealed class DatabaseOutageCollection : ICollectionFixture<DatabaseOutageFixture>
{
    public const string Name = "database-outage";
}

[Collection(DatabaseOutageCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class DatabaseOutageTests(DatabaseOutageFixture fixture)
{
    private const string Scopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task DatabaseDown_EverySurfaceFailsClosedWithAStandard503_ThenRecoversWithTheSameSessionsAndTokens()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        await ClientFlow.SignInAsync(Stack, browser, Stack.PanoOrigin, user);
        var tokens = await pano.SignInAsync(browser, user, Scopes);
        Assert.Equal(HttpStatusCode.OK, (await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        var sessionCookie = browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!.Value;
        using var anonymous = Stack.NewBrowser();
        var loginForm = await anonymous.GetAsync($"{Stack.IamOrigin}/account/login");

        await Stack.IamDatabaseRelay!.InterruptAsync();
        try
        {
            // Liveness says the process is up; readiness says it cannot serve.
            Assert.Equal(HttpStatusCode.OK, (await anonymous.GetAsync($"{Stack.IamOrigin}/health/live")).Status);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await anonymous.GetAsync($"{Stack.IamOrigin}/health/ready")).Status);

            // Browser pages: a static 503 document. The session is neither honoured nor thrown away.
            var manage = await browser.GetAsync($"{Stack.IamOrigin}/manage");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, manage.Status);
            Assert.Equal("5", manage.Header("Retry-After"));
            Assert.Contains("no-store", manage.Header("Cache-Control"));
            Assert.Contains("Temporarily unavailable", manage.Text);
            Assert.DoesNotContain(user.DisplayName, manage.Body);
            Assert.DoesNotContain(user.Email, manage.Body);
            Assert.Null(manage.Header("Set-Cookie"));
            Assert.Equal(sessionCookie, browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!.Value);

            // Signing in is not possible, and the answer does not depend on whether the password was right.
            var signIn = await anonymous.SubmitAsync(loginForm, "form[action*='/account/login']", new Dictionary<string, string> { ["Input.Email"] = user.Email, ["Input.Password"] = user.Password });
            Assert.Equal(HttpStatusCode.ServiceUnavailable, signIn.Status);
            Assert.Null(anonymous.Cookie(Stack.IamOrigin, SessionDefaults.CookieName));

            // An authorization request in the browser gets the same page; it is not bounced to a client.
            var authorize = await browser.GetAsync(pano.AuthorizeUrl(Scopes, Pkce.Create()), follow: false);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, authorize.Status);
            Assert.Null(authorize.Response.Headers.Location);

            // Back-channel protocol endpoints: an OAuth error object with 503, never a token and never "invalid".
            foreach (var response in new[]
                     {
                         await pano.RefreshAsync(tokens.RefreshToken),
                         await pano.IntrospectAsync(tokens.AccessToken),
                         await pano.RevokeAsync(tokens.RefreshToken),
                         await pano.UserInfoAsync(tokens.AccessToken),
                     })
            {
                Assert.Equal(HttpStatusCode.ServiceUnavailable, response.Status);
                Assert.True(response.Error == "temporarily_unavailable", $"{response.Raw.RequestMessage?.RequestUri?.AbsolutePath}: {response.Raw.Content.Headers.ContentType} {await response.Raw.Content.ReadAsStringAsync()}");
                Assert.Equal("5", response.Raw.Headers.RetryAfter?.ToString());
                Assert.False(response.Has("access_token"));
                Assert.False(response.Has("active"));
            }

            // The product API of the provider answers with a problem document.
            var api = await browser.GetAsync($"{Stack.IamOrigin}/api/account/session");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, api.Status);
            Assert.Equal("application/problem+json", api.Response.Content.Headers.ContentType?.MediaType);

            // Downstream: the resource API cannot verify the token and the application cannot verify its session.
            var notes = await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, notes.Status);
            Assert.False(notes.Raw.Headers.WwwAuthenticate.Any(), "an unverifiable token must not be reported as invalid");
            var workspace = await browser.GetAsync($"{Stack.PanoOrigin}/workspace");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, workspace.Status);
            Assert.DoesNotContain(user.DisplayName, workspace.Body);
            Assert.NotNull(browser.Cookie(Stack.PanoOrigin, "__Host-pano-session"));

            // Keys are served from memory, so clients can keep validating signatures they already trust.
            Assert.Equal(HttpStatusCode.OK, (await anonymous.GetAsync($"{Stack.IamOrigin}/.well-known/jwks")).Status);
        }
        finally
        {
            Stack.IamDatabaseRelay.Resume();
        }

        // Recovery needs no restart and no new sign-in: the first requests after the outage already succeed.
        Assert.Equal(HttpStatusCode.OK, (await anonymous.GetAsync($"{Stack.IamOrigin}/health/ready")).Status);
        var recovered = await browser.GetAsync($"{Stack.IamOrigin}/manage");
        Assert.Equal(HttpStatusCode.OK, recovered.Status);
        Assert.Equal("/manage", recovered.Url.AbsolutePath);
        Assert.Equal(sessionCookie, browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!.Value);
        Assert.True((await pano.IntrospectAsync(tokens.AccessToken)).Json.GetProperty("active").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken)).Status);
        var workspaceAgain = await browser.GetAsync($"{Stack.PanoOrigin}/workspace");
        Assert.Equal(HttpStatusCode.OK, workspaceAgain.Status);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(workspaceAgain));

        // The refresh token that was presented during the outage was not consumed and not treated as reused.
        var refreshed = await pano.RefreshAsync(tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal(HttpStatusCode.OK, (await pano.ApiAsync(HttpMethod.Get, "/notes", refreshed.AccessToken)).Status);
        using var signInAgain = Stack.NewBrowser();
        Assert.Equal("/manage", (await Stack.SignInAsync(signInAgain, user)).Url.AbsolutePath);
    }
}
