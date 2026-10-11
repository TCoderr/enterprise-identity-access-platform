using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using Halka.Iam.Data;
using Halka.Iam.Ops;
using Halka.Iam.Sessions;
using Halka.Migrator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Halka.IntegrationTests.Stage9;

[Collection(OpsCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Database)]
public sealed class RetentionTests(OpsFixture fixture)
{
    private const string Scopes = "openid profile offline_access workspace.read";

    private HalkaStack Stack => fixture.Stack;

    private sealed record Footprint(int Sessions, int Grants, int Authorizations, int Tokens, int OneTimeTokens, int Audit);

    private Task<Footprint> FootprintAsync(Guid userId)
        => Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            var subject = userId.ToString();
            return new Footprint(
                await db.UserSessions.CountAsync(x => x.UserId == userId),
                await db.SessionGrants.CountAsync(x => x.UserId == userId),
                await db.Authorizations.CountAsync(x => x.Subject == subject),
                await db.Tokens.CountAsync(x => x.Subject == subject),
                await db.OneTimeTokens.CountAsync(x => x.UserId == userId),
                await db.AuditEvents.CountAsync(x => x.ActorId == subject || x.TargetId == subject));
        });

    private Task<RetentionResult> RunAsync()
        => Stack.InIamAsync(services => services.GetRequiredService<RetentionService>().RunOnceAsync(CancellationToken.None));

    [Fact]
    public async Task Retention_RemovesOnlyDeadRecords_InStages_AndNeverTheAuditLogOrLiveState()
    {
        var retention = Stack.Iam.Services.GetRequiredService<IOptions<RetentionOptions>>().Value;

        // "Active" keeps a session and a token family and never signs out. "Leaver" resets the password, which
        // consumes a one-time token, delivers a mail and ends the session explicitly.
        var active = await Stack.CreateUserAsync();
        using var activeBrowser = Stack.NewBrowser();
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(activeBrowser, active, Scopes);
        var leaver = await Stack.CreateUserAsync();
        using var leaverBrowser = Stack.NewBrowser();
        await Stack.SignInAsync(leaverBrowser, leaver);
        var (_, mail) = await ResetFlow.RequestAsync(Stack, leaverBrowser, leaver.Email);
        var leaverPassword = ResetFlow.NewPassword();
        await ResetFlow.SubmitAsync(leaverBrowser, await leaverBrowser.GetAsync(mail!.Link), leaverPassword);
        var mailId = Guid.Parse(mail.MessageId);
        Task<bool> MailRowExistsAsync() => Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().OutboxMessages.AnyAsync(x => x.Id == mailId));

        // Stage 0: a run right away removes nothing of this and leaves live state usable.
        var activeBefore = await FootprintAsync(active.Id);
        var leaverBefore = await FootprintAsync(leaver.Id);
        Assert.Equal(1, activeBefore.Sessions);
        Assert.True(activeBefore.Tokens >= 2);
        await RunAsync();
        Assert.Equal(activeBefore, await FootprintAsync(active.Id));
        Assert.Equal(leaverBefore, await FootprintAsync(leaver.Id));
        Assert.True((await pano.IntrospectAsync(tokens.AccessToken)).Json.GetProperty("active").GetBoolean());
        Assert.Equal("/manage", (await activeBrowser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // Stage 1: the session timed out long ago. It is closed (not deleted) and its grant is revoked.
        Stack.Time.Advance(retention.Tokens - TimeSpan.FromDays(1));
        var closing = await RunAsync();
        Assert.True(closing.ClosedSessions >= 1);
        var closed = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.AsNoTracking().SingleAsync(x => x.UserId == active.Id));
        Assert.Equal(Stack.Time.GetUtcNow().AsStored(), closed.RevokedAt);
        Assert.Equal(SessionEndReason.AbsoluteTimeout, closed.RevokedReason);
        var grant = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().SessionGrants.AsNoTracking().SingleAsync(x => x.UserId == active.Id));
        Assert.NotNull(grant.RevokedAt);
        var authorizationStatus = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Authorizations.Where(x => x.Id == grant.AuthorizationId).Select(x => x.Status).SingleAsync());
        Assert.Equal(OpenIddictConstants.Statuses.Revoked, authorizationStatus);
        var afterClosing = await FootprintAsync(active.Id);
        Assert.Equal(activeBefore.Tokens, afterClosing.Tokens);
        Assert.Equal(1, afterClosing.Authorizations);

        // Stage 2: token retention has passed. Tokens, the authorization and its grant link are gone.
        Stack.Time.Advance(TimeSpan.FromDays(2));
        var pruning = await RunAsync();
        Assert.True(pruning.Tokens >= activeBefore.Tokens);
        Assert.True(pruning.Authorizations >= 1);
        var afterPruning = await FootprintAsync(active.Id);
        Assert.Equal(0, afterPruning.Tokens);
        Assert.Equal(0, afterPruning.Authorizations);
        Assert.Equal(0, afterPruning.Grants);
        Assert.Equal(1, afterPruning.Sessions);
        Assert.Equal(leaverBefore.OneTimeTokens, (await FootprintAsync(leaver.Id)).OneTimeTokens);
        Assert.True(await MailRowExistsAsync());

        // Stage 3: record retention has passed for what ended on day 0, but not for the session closed in stage 1.
        Stack.Time.Advance(retention.Records - retention.Tokens);
        var records = await RunAsync();
        Assert.True(records.Sessions >= 1);
        Assert.True(records.OneTimeTokens >= 1);
        Assert.True(records.Mail >= 1);
        var leaverAfter = await FootprintAsync(leaver.Id);
        Assert.Equal(0, leaverAfter.Sessions);
        Assert.Equal(0, leaverAfter.OneTimeTokens);
        Assert.False(await MailRowExistsAsync());
        Assert.Equal(1, (await FootprintAsync(active.Id)).Sessions);

        // Stage 4: now the closed session is old enough as well.
        Stack.Time.Advance(retention.Tokens);
        await RunAsync();
        var activeAfter = await FootprintAsync(active.Id);
        Assert.Equal(0, activeAfter.Sessions);

        // The audit trail is complete, the accounts and the remembered consent are intact, and both can sign in.
        Assert.True(activeAfter.Audit >= activeBefore.Audit);
        Assert.True(leaverAfter.Audit >= leaverBefore.Audit);
        var consent = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().Consents.AsNoTracking().SingleAsync(x => x.UserId == active.Id));
        Assert.Null(consent.RevokedAt);
        using var again = Stack.NewBrowser();
        var fresh = await pano.SignInAsync(again, active, Scopes);
        Assert.True((await pano.IntrospectAsync(fresh.AccessToken)).Json.GetProperty("active").GetBoolean());
        using var leaverAgain = Stack.NewBrowser();
        Assert.Equal("/manage", (await Stack.SignInAsync(leaverAgain, leaver with { Password = leaverPassword })).Url.AbsolutePath);
    }
}

[Collection(OpsCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class TelemetryTests(OpsFixture fixture)
{
    private const string Scopes = "openid profile email offline_access workspace.read";

    private static readonly Dictionary<string, string[]> AllowedTagValues = new(StringComparer.Ordinal)
    {
        ["factor"] = ["password"],
        ["outcome"] = ["success", "rejected", "throttled", "issued", "delivered", "failed"],
        ["grant_type"] = ["authorization_code", "refresh_token", "client_credentials", "other"],
        ["kind"] = ["session", "grant"],
    };

    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Metrics_CountSecurityEvents_WithFixedLowCardinalityTagsOnly()
    {
        var measurements = new ConcurrentQueue<(string Instrument, long Value, KeyValuePair<string, object?>[] Tags)>();
        var factory = Stack.Iam.Services.GetRequiredService<IMeterFactory>();
        _ = Stack.Iam.Services.GetRequiredService<IamMetrics>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, self) =>
        {
            // Only the meter of this stack's identity provider; other stacks run in the same process.
            if (instrument.Meter.Name == IamMetrics.MeterName && ReferenceEquals(instrument.Meter.Scope, factory))
            {
                self.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => measurements.Enqueue((instrument.Name, value, tags.ToArray())));
        listener.Start();

        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, user with { Password = "wrong-password-for-metrics" });
        using var pano = ProtocolClient.Pano(Stack);
        var tokens = await pano.SignInAsync(browser, user, Scopes);
        Assert.Equal(HttpStatusCode.OK, (await pano.RefreshAsync(tokens.RefreshToken)).Status);
        using var machine = new ProtocolClient(Stack, DemoCatalog.OpsMachineClientId, Stack.Demo.OpsMachineSecret, string.Empty);
        Assert.Equal(HttpStatusCode.OK, (await machine.ClientCredentialsAsync("workspace.jobs")).Status);
        await ResetFlow.RequestAsync(Stack, browser, user.Email);
        var manage = await browser.GetAsync($"{Stack.IamOrigin}/manage");
        await browser.SubmitAsync(manage, "form[action*='/account/logout']");

        bool Seen(string instrument, params (string Key, string Value)[] tags)
            => measurements.Any(m => m.Instrument == instrument && tags.All(tag => m.Tags.Any(t => t.Key == tag.Key && (string?)t.Value == tag.Value)));

        Assert.True(Seen("halka.signin.attempts", ("factor", "password"), ("outcome", "rejected")));
        Assert.True(Seen("halka.signin.attempts", ("factor", "password"), ("outcome", "success")));
        Assert.True(Seen("halka.token.requests", ("grant_type", "authorization_code"), ("outcome", "issued")));
        Assert.True(Seen("halka.token.requests", ("grant_type", "refresh_token"), ("outcome", "issued")));
        Assert.True(Seen("halka.token.requests", ("grant_type", "client_credentials"), ("outcome", "issued")));
        Assert.True(Seen("halka.outbox.deliveries", ("outcome", "delivered")));
        Assert.True(Seen("halka.revocations", ("kind", "session")));

        // Every tag is one of a few fixed words: no user, client, session or token identifier can become a label.
        Assert.All(measurements, measurement =>
        {
            Assert.Equal(1, measurement.Value);
            Assert.All(measurement.Tags, tag =>
            {
                Assert.True(AllowedTagValues.TryGetValue(tag.Key, out var allowed), $"unexpected tag '{tag.Key}'");
                Assert.Contains((string?)tag.Value, allowed);
            });
        });
    }

    [Fact]
    public async Task Logs_AndAudit_ContainNoCredentialTokenOrPersonalData()
    {
        var email = $"signup-{Guid.NewGuid():N}@example.test";
        var password = ResetFlow.NewPassword();
        using var browser = Stack.NewBrowser();

        // Sign-up, a failed and a successful sign-in, second factor enrollment and use, tokens, API call, reset.
        var register = await browser.GetAsync($"{Stack.IamOrigin}/account/register");
        await browser.SubmitAsync(register, "form[action*='/account/register']", new Dictionary<string, string>
        {
            ["Input.DisplayName"] = "Private Person Name",
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });
        var confirmation = await Stack.ReceiveMailAsync(email, Halka.Iam.Mail.MailKind.ConfirmEmail);
        await browser.SubmitAsync(await browser.GetAsync(confirmation.Link), "form[action*='/account/confirm-email']");
        var user = new TestUser(Guid.Empty, email, "Private Person Name", password);
        const string wrongPassword = "wrong-password-attempt-9911";
        await Stack.SignInAsync(browser, user with { Password = wrongPassword });
        Assert.Equal("/manage", (await Stack.SignInAsync(browser, user)).Url.AbsolutePath);
        var sessionCookie = browser.Cookie(Stack.IamOrigin, SessionDefaults.CookieName)!.Value;
        var (device, recoveryCodes) = await MfaFlow.EnrollAsync(Stack, browser);
        var enrollmentCode = device.LastCode();

        using var pano = ProtocolClient.Pano(Stack);
        var pkce = Pkce.Create();
        var outcome = await pano.AuthorizeAsync(browser, pano.AuthorizeUrl(Scopes, pkce), user: null);
        var tokens = await pano.ExchangeCodeAsync(outcome.Code!, pkce.Verifier);
        await pano.ApiAsync(HttpMethod.Get, "/notes", tokens.AccessToken);
        await pano.UserInfoAsync(tokens.AccessToken);
        var refreshed = await pano.RefreshAsync(tokens.RefreshToken);
        await pano.RevokeAsync(refreshed.RefreshToken);

        using var recovery = Stack.NewBrowser();
        var (_, resetMail) = await ResetFlow.RequestAsync(Stack, recovery, email);
        var newPassword = ResetFlow.NewPassword();
        await ResetFlow.SubmitAsync(recovery, await recovery.GetAsync(resetMail!.Link), newPassword);

        var secrets = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["password"] = password,
            ["wrong password attempt"] = wrongPassword,
            ["new password"] = newPassword,
            ["e-mail address"] = email,
            ["display name"] = "Private Person Name",
            ["session cookie"] = sessionCookie,
            ["authenticator secret"] = device.Base32,
            ["authenticator code"] = enrollmentCode,
            ["authorization code"] = outcome.Code!,
            ["code verifier"] = pkce.Verifier,
            ["access token"] = tokens.AccessToken,
            ["refresh token"] = tokens.RefreshToken,
            ["rotated refresh token"] = refreshed.RefreshToken,
            ["ID token"] = tokens.IdToken,
            ["client secret"] = pano.ClientSecret,
            ["confirmation token"] = ResetFlow.RawToken(confirmation),
            ["reset token"] = ResetFlow.RawToken(resetMail),
        };
        foreach (var (index, code) in recoveryCodes.Index())
        {
            secrets[$"recovery code {index}"] = code;
        }

        var logs = string.Join('\n', Stack.Logs.Lines);
        Assert.NotEmpty(logs);
        Assert.All(secrets, secret => Assert.False(logs.Contains(secret.Value, StringComparison.Ordinal), $"The logs contain the {secret.Key}."));

        var audit = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().AuditEvents.AsNoTracking().ToListAsync());
        Assert.NotEmpty(audit);
        var auditText = string.Join('\n', audit.Select(entry => $"{entry.ActorType}|{entry.ActorId}|{entry.Action}|{entry.TargetType}|{entry.TargetId}|{entry.Outcome}|{entry.CorrelationId}|{entry.Reason}"));
        Assert.All(secrets, secret => Assert.False(auditText.Contains(secret.Value, StringComparison.Ordinal), $"The audit log contains the {secret.Key}."));

        // No e-mail address or network address of anyone, in either place.
        Assert.DoesNotContain("@example.test", auditText);
        Assert.DoesNotContain("127.0.0.1", auditText);
        Assert.DoesNotContain("@example.test", logs);
    }
}
