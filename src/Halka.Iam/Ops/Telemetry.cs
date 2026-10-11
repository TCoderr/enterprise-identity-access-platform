using System.Diagnostics.Metrics;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Halka.Iam.Ops;

/// <summary>
/// Metrics of the identity provider. Every tag value comes from a small fixed set (outcome, grant type, reason
/// kind). User, client, session and token identifiers are never used as tags, so cardinality stays bounded and
/// no personal data reaches a metrics backend.
/// </summary>
public sealed class IamMetrics : IDisposable
{
    public const string MeterName = "Halka.Iam";

    private readonly Meter _meter;
    private readonly Counter<long> _signIns;
    private readonly Counter<long> _tokens;
    private readonly Counter<long> _revocations;
    private readonly Counter<long> _mail;

    public IamMetrics(IMeterFactory factory)
    {
        _meter = factory.Create(MeterName);
        _signIns = _meter.CreateCounter<long>("halka.signin.attempts", description: "Password sign-in attempts by outcome.");
        _tokens = _meter.CreateCounter<long>("halka.token.requests", description: "Token requests that reached the product rules, by grant type and outcome.");
        _revocations = _meter.CreateCounter<long>("halka.revocations", description: "Revocation operations by kind.");
        _mail = _meter.CreateCounter<long>("halka.outbox.deliveries", description: "Demo mail deliveries by outcome.");
    }

    public void SignIn(string factor, string outcome)
        => _signIns.Add(1, new KeyValuePair<string, object?>("factor", factor), new KeyValuePair<string, object?>("outcome", outcome));

    public void Token(string grantType, string outcome)
        => _tokens.Add(1, new KeyValuePair<string, object?>("grant_type", grantType), new KeyValuePair<string, object?>("outcome", outcome));

    public void Revocation(string kind) => _revocations.Add(1, new KeyValuePair<string, object?>("kind", kind));

    public void Mail(string outcome) => _mail.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    public void Dispose() => _meter.Dispose();
}

public sealed class RetentionOptions
{
    public const string SectionName = "Retention";

    /// <summary>Tokens and ad-hoc authorizations that are no longer valid are deleted after this age.</summary>
    public TimeSpan Tokens { get; set; } = TimeSpan.FromDays(14);

    /// <summary>Ended sessions, used or expired one-time tokens, challenges and delivered mail are deleted after this age.</summary>
    public TimeSpan Records { get; set; } = TimeSpan.FromDays(30);

    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(24);

    public bool WorkerEnabled { get; set; } = true;
}

public sealed record RetentionResult(int ClosedSessions, long Tokens, long Authorizations, int Sessions, int OneTimeTokens, int Challenges, int Mail, int ClientSecrets);

/// <summary>
/// Removes data that no longer has a purpose. Only records that are already unusable are deleted (revoked,
/// expired, consumed, delivered); nothing that could still authorise a request. The audit log is never touched.
/// </summary>
public sealed class RetentionService(
    IamDbContext db,
    RevocationService revocation,
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations,
    TimeProvider time,
    IOptions<RetentionOptions> options,
    IOptions<CentralSessionOptions> sessionOptions)
{
    public async Task<RetentionResult> RunOnceAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var tokenCutoff = now - options.Value.Tokens;
        var recordCutoff = now - options.Value.Records;

        // Timed-out sessions are closed first, which revokes their grants like an explicit sign-out would.
        var closed = await revocation.CloseExpiredSessionsAsync(sessionOptions.Value.IdleTimeout, cancellationToken);

        // OpenIddict removes tokens that are expired or not valid any more, and authorizations that are not valid.
        var prunedTokens = await tokens.PruneAsync(tokenCutoff, cancellationToken);
        var prunedAuthorizations = await authorizations.PruneAsync(tokenCutoff, cancellationToken);

        var sessions = await db.UserSessions
            .Where(x => x.RevokedAt != null && x.RevokedAt < recordCutoff)
            .ExecuteDeleteAsync(cancellationToken);
        var oneTimeTokens = await db.OneTimeTokens
            .Where(x => (x.ConsumedAt != null && x.ConsumedAt < recordCutoff) || x.ExpiresAt < recordCutoff)
            .ExecuteDeleteAsync(cancellationToken);
        var challenges = await db.MfaChallenges.Where(x => x.ExpiresAt < recordCutoff).ExecuteDeleteAsync(cancellationToken);
        var mail = await db.OutboxMessages.Where(x => x.DeliveredAt != null && x.DeliveredAt < recordCutoff).ExecuteDeleteAsync(cancellationToken);
        var secrets = await db.ClientSecrets.Where(x => x.NotAfter < recordCutoff || (x.RevokedAt != null && x.RevokedAt < recordCutoff)).ExecuteDeleteAsync(cancellationToken);
        return new RetentionResult(closed, prunedTokens, prunedAuthorizations, sessions, oneTimeTokens, challenges, mail, secrets);
    }
}

public sealed class RetentionWorker(IServiceScopeFactory scopes, IOptions<RetentionOptions> options, TimeProvider time, ILogger<RetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.WorkerEnabled)
        {
            return;
        }

        // One run at start, then one per interval.
        using var timer = new PeriodicTimer(options.Value.Interval, time);
        try
        {
            do
            {
                try
                {
                    await using var scope = scopes.CreateAsyncScope();
                    var result = await scope.ServiceProvider.GetRequiredService<RetentionService>().RunOnceAsync(stoppingToken);
                    logger.LogInformation(
                        "Retention closed {Closed} expired sessions and removed {Tokens} tokens, {Authorizations} authorizations, {Sessions} sessions.",
                        result.ClosedSessions, result.Tokens, result.Authorizations, result.Sessions);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    logger.LogError("Retention run failed ({ErrorType}).", exception.GetType().Name);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
