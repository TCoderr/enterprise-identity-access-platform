using System.Text.Json;
using Halka.Iam.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Mail;

public sealed class MailOptions
{
    public const string SectionName = "Mail";

    /// <summary>Private directory of the demo mail sink. No real e-mail is ever sent.</summary>
    public string SinkDirectory { get; set; } = string.Empty;

    public bool WorkerEnabled { get; set; } = true;

    public int MaxAttempts { get; set; } = 5;

    public int LeaseSeconds { get; set; } = 30;

    public int PollSeconds { get; set; } = 2;

    public int BatchSize { get; set; } = 10;
}

public static class MailKind
{
    public const string ConfirmEmail = "confirm_email";
    public const string ResetPassword = "reset_password";
}

public sealed record MailPayload(string Kind, Guid UserId, string To, string Subject, string Link);

public sealed record LeasedMail(Guid Id, long LeaseVersion, int Attempts, MailPayload Payload);

public interface IMailSink
{
    /// <summary>Delivers a message. Must be idempotent for a given message id (delivery is at-least-once).</summary>
    Task DeliverAsync(Guid messageId, MailPayload payload, CancellationToken cancellationToken);
}

/// <summary>
/// Transactional outbox for demo mail. Messages are staged in the caller's unit of work, so the business effect and
/// the message commit together. The payload (recipient and one-time link) is protected at rest.
/// </summary>
public sealed class MailOutbox(IamDbContext db, TimeProvider time, IDataProtectionProvider protection)
{
    private readonly IDataProtector _protector = protection.CreateProtector("Halka.Iam.Mail.Outbox.v1");

    public void Enqueue(MailPayload payload)
    {
        var now = time.GetUtcNow();
        db.OutboxMessages.Add(new OutboxMessage
        {
            Id = Guid.NewGuid(),
            Kind = payload.Kind,
            ProtectedPayload = _protector.Protect(JsonSerializer.SerializeToUtf8Bytes(payload)),
            CreatedAt = now,
            AvailableAt = now,
        });
    }

    internal MailPayload Unprotect(byte[] protectedPayload)
        => JsonSerializer.Deserialize<MailPayload>(_protector.Unprotect(protectedPayload))
           ?? throw new InvalidOperationException("Outbox payload could not be read.");
}

/// <summary>
/// Leases and delivers outbox messages. A lease is a conditional UPDATE (only one worker can win a row) that also
/// increments <see cref="OutboxMessage.LeaseVersion"/>; completion and failure are only recorded for that exact
/// version (fencing), so a worker that lost its lease cannot overwrite the state written by its successor.
/// </summary>
public sealed class OutboxDispatcher(
    IamDbContext db,
    MailOutbox outbox,
    IMailSink sink,
    TimeProvider time,
    IOptions<MailOptions> options,
    Halka.Iam.Ops.IamMetrics metrics,
    ILogger<OutboxDispatcher> logger)
{
    public async Task<IReadOnlyList<LeasedMail>> LeaseAsync(string owner, CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var now = time.GetUtcNow();
        var until = now.AddSeconds(settings.LeaseSeconds);

        var candidates = await db.OutboxMessages.AsNoTracking()
            .Where(x => x.DeliveredAt == null && x.DeadAt == null && x.AvailableAt <= now
                        && (x.LeaseUntil == null || x.LeaseUntil < now))
            .OrderBy(x => x.CreatedAt)
            .Select(x => x.Id)
            .Take(settings.BatchSize)
            .ToListAsync(cancellationToken);

        var leased = new List<LeasedMail>(candidates.Count);
        foreach (var id in candidates)
        {
            var won = await db.OutboxMessages
                .Where(x => x.Id == id && x.DeliveredAt == null && x.DeadAt == null && x.AvailableAt <= now
                            && (x.LeaseUntil == null || x.LeaseUntil < now))
                .ExecuteUpdateAsync(set => set
                    .SetProperty(x => x.LeaseOwner, owner)
                    .SetProperty(x => x.LeaseUntil, until)
                    .SetProperty(x => x.LeaseVersion, x => x.LeaseVersion + 1)
                    .SetProperty(x => x.Attempts, x => x.Attempts + 1), cancellationToken);
            if (won != 1)
            {
                continue;
            }

            var row = await db.OutboxMessages.AsNoTracking()
                .Where(x => x.Id == id && x.LeaseOwner == owner)
                .Select(x => new { x.LeaseVersion, x.Attempts, x.ProtectedPayload })
                .SingleOrDefaultAsync(cancellationToken);
            if (row is not null)
            {
                leased.Add(new LeasedMail(id, row.LeaseVersion, row.Attempts, outbox.Unprotect(row.ProtectedPayload)));
            }
        }

        return leased;
    }

    /// <summary>Records a successful delivery. Returns false when the lease was lost (nothing is changed).</summary>
    public async Task<bool> CompleteAsync(LeasedMail mail, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var updated = await db.OutboxMessages
            .Where(x => x.Id == mail.Id && x.LeaseVersion == mail.LeaseVersion && x.DeliveredAt == null)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.DeliveredAt, now)
                .SetProperty(x => x.LeaseOwner, (string?)null)
                .SetProperty(x => x.LeaseUntil, (DateTimeOffset?)null)
                .SetProperty(x => x.LastErrorCode, (string?)null), cancellationToken);
        return updated == 1;
    }

    /// <summary>Records a failed attempt: schedules a retry with exponential backoff or dead-letters the message.</summary>
    public async Task<bool> FailAsync(LeasedMail mail, string errorCode, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var dead = mail.Attempts >= options.Value.MaxAttempts;
        var retryAt = now.AddSeconds(Math.Min(300, 5 * Math.Pow(2, mail.Attempts - 1)));
        var updated = await db.OutboxMessages
            .Where(x => x.Id == mail.Id && x.LeaseVersion == mail.LeaseVersion && x.DeliveredAt == null)
            .ExecuteUpdateAsync(set => set
                .SetProperty(x => x.DeadAt, dead ? now : (DateTimeOffset?)null)
                .SetProperty(x => x.AvailableAt, dead ? now : retryAt)
                .SetProperty(x => x.LeaseOwner, (string?)null)
                .SetProperty(x => x.LeaseUntil, (DateTimeOffset?)null)
                .SetProperty(x => x.LastErrorCode, errorCode), cancellationToken);
        return updated == 1;
    }

    /// <summary>Leases one batch and delivers it. Returns the number of delivered messages.</summary>
    public async Task<int> DispatchOnceAsync(string owner, CancellationToken cancellationToken)
    {
        var delivered = 0;
        foreach (var mail in await LeaseAsync(owner, cancellationToken))
        {
            try
            {
                await sink.DeliverAsync(mail.Id, mail.Payload, cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // The exception message may contain file paths; only its type name is persisted and logged.
                logger.LogWarning("Mail delivery failed for outbox message {MessageId} ({ErrorType}).", mail.Id, exception.GetType().Name);
                await FailAsync(mail, exception.GetType().Name, cancellationToken);
                metrics.Mail("failed");
                continue;
            }

            if (await CompleteAsync(mail, cancellationToken))
            {
                delivered++;
                metrics.Mail("delivered");
            }
        }

        return delivered;
    }
}

/// <summary>Background delivery loop. Stops promptly on shutdown; undelivered messages stay in the outbox.</summary>
public sealed class OutboxWorker(
    IServiceScopeFactory scopes,
    IOptions<MailOptions> options,
    TimeProvider time,
    ILogger<OutboxWorker> logger) : BackgroundService
{
    private readonly string _owner = $"worker-{Guid.NewGuid():N}"[..23];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.WorkerEnabled)
        {
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, options.Value.PollSeconds)), time);
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var dispatcher = scope.ServiceProvider.GetRequiredService<OutboxDispatcher>();
                await dispatcher.DispatchOnceAsync(_owner, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError("Outbox worker iteration failed ({ErrorType}).", exception.GetType().Name);
                if (Halka.Shared.StoreFailures.IsUnavailable(exception))
                {
                    await using var scope = scopes.CreateAsyncScope();
                    Halka.Iam.Ops.StorePool.DropIdleConnections(scope.ServiceProvider.GetRequiredService<IamDbContext>(), logger);
                }
            }
        }
        while (await WaitAsync(timer, stoppingToken));
    }

    private static async Task<bool> WaitAsync(PeriodicTimer timer, CancellationToken stoppingToken)
    {
        try
        {
            return await timer.WaitForNextTickAsync(stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}

/// <summary>
/// Demo mail sink: one JSON file per message in a private directory. Writing the same message twice overwrites the
/// same file, which makes at-least-once delivery harmless.
/// </summary>
public sealed class FileMailSink(IOptions<MailOptions> options, TimeProvider time) : IMailSink
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public async Task DeliverAsync(Guid messageId, MailPayload payload, CancellationToken cancellationToken)
    {
        var directory = options.Value.SinkDirectory;
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException("Mail:SinkDirectory is not configured.");
        }

        Directory.CreateDirectory(directory);
        var target = Path.Combine(directory, $"{messageId:N}.json");
        var temporary = target + ".tmp";
        var document = new
        {
            messageId,
            kind = payload.Kind,
            to = payload.To,
            subject = payload.Subject,
            link = payload.Link,
            deliveredAt = time.GetUtcNow(),
        };
        await File.WriteAllBytesAsync(temporary, JsonSerializer.SerializeToUtf8Bytes(document, Json), cancellationToken);
        File.Move(temporary, target, overwrite: true);
    }
}
