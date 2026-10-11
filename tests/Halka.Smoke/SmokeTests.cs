using System.Net;
using System.Text.Json;
using Halka.Iam.Mail;
using Halka.Iam.Sessions;

namespace Halka.Smoke;

public static class Phase
{
    public const string Trait = "Phase";
    public const string Up = "up";
    public const string Restarted = "restarted";
    public const string DatabaseDown = "db-down";
    public const string DatabaseRecovered = "db-recovered";
    public const string ProviderDown = "op-down";
    public const string ProviderRecovered = "op-recovered";
}

public sealed record SmokeState(string SessionCookie, string Email, string Password);

/// <summary>Application cookie of a browser that signed in to Pano, kept to check restarts and outages.</summary>
public sealed record PanoState(string Cookie, string DisplayName)
{
    public const string CookieName = "__Host-pano-session";

    public static async Task<(Browser Browser, PanoState State)> RestoreAsync(SmokeEnvironment env)
    {
        var state = JsonSerializer.Deserialize<PanoState>(await File.ReadAllTextAsync(env.PanoStatePath))!;
        var browser = env.NewBrowser();
        browser.Cookies.Add(new Uri(env.PanoOrigin), new Cookie(CookieName, state.Cookie, "/") { Secure = true, HttpOnly = true });
        return (browser, state);
    }
}

/// <summary>Checks against the freshly initialised Compose stack (empty volume, images just built).</summary>
[Trait(Phase.Trait, Phase.Up)]
public sealed class UpPhase
{
    private static SmokeEnvironment Env => SmokeEnvironment.Current;

    [Fact]
    public async Task Stack_IsReady_OverHttpsWithTheLocalCa_AndCookiesAreSecure()
    {
        using var browser = Env.NewBrowser();

        var ready = await browser.GetAsync($"{Env.IamOrigin}/health/ready");
        var login = await browser.GetAsync($"{Env.IamOrigin}/account/login");

        Assert.Equal(HttpStatusCode.OK, ready.Status);
        Assert.Equal(HttpStatusCode.OK, login.Status);
        var setCookies = login.Response.Headers.GetValues("Set-Cookie").ToList();
        Assert.NotEmpty(setCookies);
        Assert.All(setCookies, cookie =>
        {
            Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith("__Host-", cookie);
        });
        Assert.Contains("max-age", login.Header("Strict-Transport-Security"));
    }

    [Fact]
    public async Task HostHeader_OtherThanThePublicHost_IsRejected()
    {
        // HttpClient derives the TLS server name from the Host header, so the mismatch is sent on a raw TLS stream:
        // the handshake uses the real host name, the HTTP request carries a foreign Host header.
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, Env.PortBase);
        await using var tls = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, certificate, _, _) =>
        {
            using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
            chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(Env.Authority);
            chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            using var leaf = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate!);
            return chain.Build(leaf);
        });
        await tls.AuthenticateAsClientAsync("id.halka.localhost");
        await tls.WriteAsync(System.Text.Encoding.ASCII.GetBytes("GET /account/login HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"));
        using var reader = new StreamReader(tls, System.Text.Encoding.ASCII);
        var statusLine = await reader.ReadLineAsync();

        Assert.NotNull(statusLine);
        Assert.StartsWith("HTTP/1.1 400", statusLine);
    }

    [Fact]
    public async Task SeedAccount_SignsIn_AndSignupWorksThroughThePrivateMailSink()
    {
        using var seeded = Env.NewBrowser();
        var landing = await SignInAsync(seeded, Env.SeedUser("alice@halka.test"));
        Assert.Equal("/manage", landing.Url.AbsolutePath);
        Assert.True(seeded.Cookie(Env.IamOrigin, SessionDefaults.CookieName)!.Secure);

        var email = $"smoke-{Guid.NewGuid():N}@example.test";
        var password = $"Pw-{Guid.NewGuid():N}";
        using var browser = Env.NewBrowser();
        var form = await browser.GetAsync($"{Env.IamOrigin}/account/register");
        await browser.SubmitAsync(form, "form[action*='/account/register']", new Dictionary<string, string>
        {
            ["Input.DisplayName"] = "Smoke Person",
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });
        var mail = await Env.WaitForMailAsync(email, MailKind.ConfirmEmail);
        var confirmed = await browser.SubmitAsync(await browser.GetAsync(mail.Link), "form[action*='/account/confirm-email']");
        Assert.Equal("/account/login", confirmed.Url.AbsolutePath);

        var signedIn = await SignInAsync(browser, new TestUser(Guid.Empty, email, "Smoke Person", password));
        Assert.Equal("/manage", signedIn.Url.AbsolutePath);

        // Kept (in the private directory) to prove after a restart that sessions and keys are persistent.
        var cookie = browser.Cookie(Env.IamOrigin, SessionDefaults.CookieName)!.Value;
        await File.WriteAllTextAsync(Env.StatePath, JsonSerializer.Serialize(new SmokeState(cookie, email, password)));
    }

    [Fact]
    public async Task Sso_AcrossContainers_PanoThenRaporWithoutASecondSignIn_AndTheApiAcceptsTheirTokens()
    {
        var alice = Env.SeedUser("alice@halka.test");
        using var browser = Env.NewBrowser();

        // Pano redirects to the identity provider, exchanges the code container-to-container (the provider's
        // public host name resolves inside the Compose network) and validates the ID token against its JWKS.
        var pano = await ClientFlow.SignInAsync(Env.IamOrigin, browser, Env.PanoOrigin, alice);
        Assert.Equal(new Uri(Env.PanoOrigin).Authority, pano.Url.Authority);
        Assert.Equal("Signed in to Pano", ClientFlow.Badge(pano));

        // Pano calls the resource API with its access token; the API introspects it at the provider.
        var workspace = await browser.GetAsync($"{Env.PanoOrigin}/workspace");
        var loaded = await ClientFlow.WorkspaceAsync(browser, workspace, "Load");
        Assert.Equal("200", ClientFlow.ApiStatus(loaded));

        // Rapor is another site. The central session signs the user in without showing the sign-in form again.
        var rapor = await ClientFlow.SignInAsync(Env.IamOrigin, browser, Env.RaporOrigin, user: null);
        Assert.Equal(new Uri(Env.RaporOrigin).Authority, rapor.Url.Authority);
        Assert.Equal("Signed in to Rapor", ClientFlow.Badge(rapor));

        // Without a token the API answers 401 over its own HTTPS endpoint.
        var anonymous = await browser.GetAsync($"{Env.ApiOrigin}/notes");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.Status);

        var cookie = browser.Cookie(Env.PanoOrigin, PanoState.CookieName)!;
        Assert.True(cookie.Secure);
        Assert.True(cookie.HttpOnly);
        await File.WriteAllTextAsync(Env.PanoStatePath, JsonSerializer.Serialize(new PanoState(cookie.Value, alice.DisplayName)));
    }

    [Fact]
    public async Task MachineDemo_GetsAClientCredentialsToken_AndCallsTheApi_FromItsOwnContainer()
    {
        var (exit, output) = await SmokeEnvironment.DockerAsync("compose", "-f", Env.ComposeFile, "-p", Env.Project, "--profile", "machine", "run", "--rm", "--no-deps", "machine-demo");

        Assert.True(exit == 0, $"machine demo exited with {exit}");
        Assert.All(Env.SecretValues(), secret => Assert.False(output.Contains(secret.Value, StringComparison.Ordinal), $"machine demo output contains {secret.Key}"));
    }

    [Fact]
    public async Task Containers_RunAsNonRoot_WithReadOnlyRootAndNoCapabilities()
    {
        foreach (var service in SmokeEnvironment.AppServices)
        {
            var (uidExit, uid) = await SmokeEnvironment.DockerAsync("exec", Env.Container(service), "id", "-u");
            Assert.Equal(0, uidExit);
            Assert.NotEqual("0", uid.Trim());

            var (_, inspect) = await SmokeEnvironment.DockerAsync("inspect", "--format",
                "{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapDrop}}|{{.HostConfig.Privileged}}|{{.Config.User}}", Env.Container(service));
            var parts = inspect.Trim().Split('|');
            Assert.Equal("true", parts[0]);
            Assert.Contains("ALL", parts[1]);
            Assert.Equal("false", parts[2]);
            Assert.NotEqual("root", parts[3]);
            Assert.NotEqual("0", parts[3]);

            var (writeExit, _) = await SmokeEnvironment.DockerAsync("exec", Env.Container(service), "sh", "-c", "echo x > /app/probe");
            Assert.NotEqual(0, writeExit);
        }
    }

    [Fact]
    public async Task Scanner_PositiveControl_FindsEveryPlantedLeak()
    {
        var secret = Env.SecretValues().First().Value;
        using var canary = ImageScanner.BuildCanary(secret);

        var findings = await ImageScanner.ScanTarAsync(canary, Env.SecretValues());

        Assert.Contains(findings, finding => finding.Path == "app/appsettings.Production.json" && finding.Rule.StartsWith("secret-value:", StringComparison.Ordinal));
        Assert.Contains(findings, finding => finding.Path == "app/certs/server.key" && finding.Rule == "pem-private-key");
        Assert.Contains(findings, finding => finding.Path == "app/certs/server.key" && finding.Rule == "key-file-name");
        Assert.Contains(findings, finding => finding.Path == "app/certs/signing.pfx" && finding.Rule == "key-file-name");
        Assert.DoesNotContain(findings, finding => finding.Path == "usr/lib/harmless.txt");
    }

    [Fact]
    public async Task Images_ContainNoSecretOrPrivateKeyMaterial()
    {
        // Every image built for this project, including the migrator and the machine demo that are not running.
        var (exit, images) = await SmokeEnvironment.DockerAsync("image", "ls", "--filter", $"reference={Env.Project}-*", "--format", "{{.Repository}}:{{.Tag}}");
        Assert.Equal(0, exit);
        var names = images.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(name => name.StartsWith($"{Env.Project}-", StringComparison.Ordinal))
            .Distinct()
            .ToList();
        foreach (var expected in new[] { "iam", "migrator", "workspace-api", "pano", "rapor", "machine-demo" })
        {
            Assert.Contains(names, name => name.StartsWith($"{Env.Project}-{expected}:", StringComparison.Ordinal));
        }

        foreach (var image in names)
        {
            var findings = await ImageScanner.ScanImageAsync(image, Env.SecretValues());
            Assert.True(findings.Count == 0, $"{image}: {string.Join("; ", findings.Select(finding => $"{finding.Rule} in {finding.Path}"))}");
        }
    }

    internal static async Task<Page> SignInAsync(Browser browser, TestUser user)
    {
        var login = await browser.GetAsync($"{Env.IamOrigin}/account/login");
        return await browser.SubmitAsync(login, "form[action*='/account/login']", new Dictionary<string, string>
        {
            ["Input.Email"] = user.Email,
            ["Input.Password"] = user.Password,
        });
    }
}

/// <summary>After "docker compose down" and "up" (containers recreated, volume and private directory kept).</summary>
[Trait(Phase.Trait, Phase.Restarted)]
public sealed class RestartedPhase
{
    private static SmokeEnvironment Env => SmokeEnvironment.Current;

    [Fact]
    public async Task Session_Accounts_AndKeys_SurviveARestart()
    {
        var state = JsonSerializer.Deserialize<SmokeState>(await File.ReadAllTextAsync(Env.StatePath))!;
        using var browser = Env.NewBrowser();
        browser.Cookies.Add(new Uri(Env.IamOrigin), new Cookie(SessionDefaults.CookieName, state.SessionCookie, "/") { Secure = true, HttpOnly = true });

        // The cookie issued before the restart is still decryptable (same Data Protection key ring) and its session
        // row is still present and active (same database volume).
        var account = await browser.GetAsync($"{Env.IamOrigin}/manage");
        Assert.Equal("/manage", account.Url.AbsolutePath);
        Assert.Contains(state.Email, account.Text);

        using var fresh = Env.NewBrowser();
        Assert.Equal("/manage", (await UpPhase.SignInAsync(fresh, new TestUser(Guid.Empty, state.Email, "Smoke Person", state.Password))).Url.AbsolutePath);
        Assert.Equal("/manage", (await UpPhase.SignInAsync(Env.NewBrowser(), Env.SeedUser("alice@halka.test"))).Url.AbsolutePath);
    }

    [Fact]
    public async Task ApplicationSession_Tokens_AndSigningKeys_SurviveARestart()
    {
        var (browser, state) = await PanoState.RestoreAsync(Env);
        using (browser)
        {
            // The application session row, its protected tokens and the provider's token state were all persisted.
            var workspace = await browser.GetAsync($"{Env.PanoOrigin}/workspace");
            Assert.Equal(HttpStatusCode.OK, workspace.Status);
            Assert.Equal("Signed in to Pano", ClientFlow.Badge(workspace));
            Assert.Contains(state.DisplayName, workspace.Text);
            Assert.Equal("200", ClientFlow.ApiStatus(await ClientFlow.WorkspaceAsync(browser, workspace, "Load")));
        }

        // A new sign-in works too: the recreated containers discover the provider and trust the same signing key.
        using var fresh = Env.NewBrowser();
        var rapor = await ClientFlow.SignInAsync(Env.IamOrigin, fresh, Env.RaporOrigin, Env.SeedUser("alice@halka.test"));
        Assert.Equal("Signed in to Rapor", ClientFlow.Badge(rapor));
    }

    [Fact]
    public async Task Logs_ContainNoSecretValues()
    {
        var state = JsonSerializer.Deserialize<SmokeState>(await File.ReadAllTextAsync(Env.StatePath))!;
        var (exit, logs) = await SmokeEnvironment.DockerAsync("compose", "-p", Env.Project, "logs", "--no-color", "--no-log-prefix");
        Assert.Equal(0, exit);
        Assert.True(logs.Length > 200, "expected the stack to have produced log output");

        foreach (var (name, value) in Env.SecretValues().Append(new("smoke-password", state.Password)).Append(new("smoke-session-cookie", state.SessionCookie)))
        {
            Assert.False(logs.Contains(value, StringComparison.Ordinal), $"log output contains the value of {name}");
        }

        Assert.DoesNotContain("token=", logs, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", logs, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>While the database container is stopped.</summary>
[Trait(Phase.Trait, Phase.DatabaseDown)]
public sealed class DatabaseDownPhase
{
    private static SmokeEnvironment Env => SmokeEnvironment.Current;

    [Fact]
    public async Task DatabaseOutage_FailsClosed_LivenessStaysUpReadinessGoesDown()
    {
        using var browser = Env.NewBrowser();

        var live = await browser.GetAsync($"{Env.IamOrigin}/health/live");
        var ready = await browser.GetAsync($"{Env.IamOrigin}/health/ready");
        Assert.Equal(HttpStatusCode.OK, live.Status);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.Status);

        // Signing in cannot succeed and no session cookie is issued.
        var attempt = await UpPhase.SignInAsync(browser, Env.SeedUser("alice@halka.test"));
        Assert.True((int)attempt.Status >= 500, $"expected a server error, got {(int)attempt.Status}");
        Assert.Null(browser.Cookie(Env.IamOrigin, SessionDefaults.CookieName));
        Assert.DoesNotContain("Npgsql", attempt.Body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Exception", attempt.Body, StringComparison.OrdinalIgnoreCase);

        // An existing session is not honoured from the cookie alone while its state cannot be checked.
        var state = JsonSerializer.Deserialize<SmokeState>(await File.ReadAllTextAsync(Env.StatePath))!;
        using var existing = Env.NewBrowser();
        existing.Cookies.Add(new Uri(Env.IamOrigin), new Cookie(SessionDefaults.CookieName, state.SessionCookie, "/") { Secure = true, HttpOnly = true });
        var account = await existing.GetAsync($"{Env.IamOrigin}/manage");
        Assert.True((int)account.Status >= 500, $"expected a server error, got {(int)account.Status}");
        Assert.DoesNotContain(state.Email, account.Body);
    }

    [Fact]
    public async Task DatabaseOutage_ApplicationAndApi_ShowNoProtectedContent()
    {
        var (browser, state) = await PanoState.RestoreAsync(Env);
        using (browser)
        {
            var workspace = await browser.GetAsync($"{Env.PanoOrigin}/workspace");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, workspace.Status);
            Assert.DoesNotContain(state.DisplayName, workspace.Body);
            Assert.DoesNotContain("Npgsql", workspace.Body, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(browser.Cookie(Env.PanoOrigin, PanoState.CookieName));

            // The API needs no database of its own; a request without a token is still a plain 401.
            Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync($"{Env.ApiOrigin}/notes")).Status);
        }
    }
}

/// <summary>After the database container was started again.</summary>
[Trait(Phase.Trait, Phase.DatabaseRecovered)]
public sealed class DatabaseRecoveredPhase
{
    private static SmokeEnvironment Env => SmokeEnvironment.Current;

    [Fact]
    public async Task DatabaseRecovery_RestoresReadinessAndExistingSessionsWithoutRestartingTheApp()
    {
        using var browser = Env.NewBrowser();
        var ready = await WaitForReadyAsync(browser);
        Assert.Equal(HttpStatusCode.OK, ready.Status);

        var state = JsonSerializer.Deserialize<SmokeState>(await File.ReadAllTextAsync(Env.StatePath))!;
        browser.Cookies.Add(new Uri(Env.IamOrigin), new Cookie(SessionDefaults.CookieName, state.SessionCookie, "/") { Secure = true, HttpOnly = true });
        Assert.Equal("/manage", (await browser.GetAsync($"{Env.IamOrigin}/manage")).Url.AbsolutePath);

        using var fresh = Env.NewBrowser();
        Assert.Equal("/manage", (await UpPhase.SignInAsync(fresh, Env.SeedUser("alice@halka.test"))).Url.AbsolutePath);

        // The application session that existed before the outage is usable again, without signing in.
        var (pano, _) = await PanoState.RestoreAsync(Env);
        using (pano)
        {
            var workspace = await SmokeEnvironment.WaitForStatusAsync(pano, $"{Env.PanoOrigin}/workspace", HttpStatusCode.OK);
            Assert.Equal("Signed in to Pano", ClientFlow.Badge(workspace));
            Assert.Equal("200", ClientFlow.ApiStatus(await ClientFlow.WorkspaceAsync(pano, workspace, "Load")));
        }
    }

    private static async Task<Page> WaitForReadyAsync(Browser browser)
    {
        Page page = null!;
        for (var attempt = 0; attempt < 40; attempt++)
        {
            page = await browser.GetAsync($"{Env.IamOrigin}/health/ready");
            if (page.Status == HttpStatusCode.OK)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500));
        }

        return page;
    }
}

/// <summary>While the identity provider container is stopped (database and applications keep running).</summary>
[Trait(Phase.Trait, Phase.ProviderDown)]
public sealed class ProviderDownPhase
{
    private static SmokeEnvironment Env => SmokeEnvironment.Current;

    [Fact]
    public async Task ProviderOutage_ApplicationFailsClosed_KeepsItsCookie_AndStaysHealthyItself()
    {
        var (browser, state) = await PanoState.RestoreAsync(Env);
        using (browser)
        {
            // Pano cannot confirm that its session is still valid at the provider, so it shows nothing protected.
            var workspace = await browser.GetAsync($"{Env.PanoOrigin}/workspace");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, workspace.Status);
            Assert.Contains("could not be verified", workspace.Text);
            Assert.DoesNotContain(state.DisplayName, workspace.Body);
            Assert.NotNull(browser.Cookie(Env.PanoOrigin, PanoState.CookieName));

            // The application process itself is alive and its public pages still work.
            using var visitor = Env.NewBrowser();
            var home = await visitor.GetAsync($"{Env.PanoOrigin}/");
            Assert.Equal(HttpStatusCode.OK, home.Status);
            Assert.Equal("Not signed in to Pano", ClientFlow.Badge(home));
            Assert.Equal(HttpStatusCode.Unauthorized, (await visitor.GetAsync($"{Env.ApiOrigin}/notes")).Status);
        }
    }
}

/// <summary>After the identity provider container was started again.</summary>
[Trait(Phase.Trait, Phase.ProviderRecovered)]
public sealed class ProviderRecoveredPhase
{
    private static SmokeEnvironment Env => SmokeEnvironment.Current;

    [Fact]
    public async Task ProviderRecovery_RestoresTheApplicationSession_AndNewSignIns_WithTheSameKeys()
    {
        using var probe = Env.NewBrowser();
        await SmokeEnvironment.WaitForStatusAsync(probe, $"{Env.IamOrigin}/health/ready", HttpStatusCode.OK);

        var (browser, _) = await PanoState.RestoreAsync(Env);
        using (browser)
        {
            var workspace = await SmokeEnvironment.WaitForStatusAsync(browser, $"{Env.PanoOrigin}/workspace", HttpStatusCode.OK);
            Assert.Equal("Signed in to Pano", ClientFlow.Badge(workspace));
            Assert.Equal("200", ClientFlow.ApiStatus(await ClientFlow.WorkspaceAsync(browser, workspace, "Load")));
        }

        using var fresh = Env.NewBrowser();
        var rapor = await ClientFlow.SignInAsync(Env.IamOrigin, fresh, Env.RaporOrigin, Env.SeedUser("alice@halka.test"));
        Assert.True(ClientFlow.Badge(rapor) == "Signed in to Rapor", $"landed on {rapor.Url.GetLeftPart(UriPartial.Path)} with {(int)rapor.Status}: {rapor.Find("h1")?.TextContent.Trim()}");
    }
}
