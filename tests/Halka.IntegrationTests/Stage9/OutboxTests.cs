using Halka.Iam.Data;
using Halka.Iam.Mail;
using Halka.Iam.Ops;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Halka.IntegrationTests.Stage9;

/// <summary>Stack for operational tests. Its clock may move by days; no test here signs in through a demo client.</summary>
public sealed class OpsFixture : StackFixture;

[CollectionDefinition(Name)]
public sealed class OpsCollection : ICollectionFixture<OpsFixture>
{
    public const string Name = "ops";
}

internal static class Eventually
{
    /// <summary>PostgreSQL stores timestamps with microsecond precision; .NET ticks are ten times finer.</summary>
    public static DateTimeOffset AsStored(this DateTimeOffset value) => new(value.Ticks - (value.Ticks % 10), value.Offset);

    /// <summary>Waits for an effect of a background component, with a deadline. Not used to order concurrent work.</summary>
    public static async Task TrueAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!await condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new Xunit.Sdk.XunitException($"Timed out waiting for: {what}.");
            }

            await Task.Delay(25);
        }
    }
}

/// <summary>A mail sink whose n-th call fails when the script returns an exception.</summary>
internal sealed class ScriptedSink(Func<int, Exception?> script) : IMailSink
{
    private int _calls;

    public int Calls => _calls;

    public List<Guid> Delivered { get; } = [];

    public Task DeliverAsync(Guid messageId, MailPayload payload, CancellationToken cancellationToken)
    {
        if (script(Interlocked.Increment(ref _calls)) is { } failure)
        {
            throw failure;
        }

        lock (Delivered)
        {
            Delivered.Add(messageId);
        }

        return Task.CompletedTask;
    }
}

[Collection(OpsCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Database)]
public sealed class OutboxTests(OpsFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    private static OutboxDispatcher Dispatcher(IServiceProvider services, IMailSink sink)
        => new(
            services.GetRequiredService<IamDbContext>(),
            services.GetRequiredService<MailOutbox>(),
            sink,
            services.GetRequiredService<TimeProvider>(),
            services.GetRequiredService<IOptions<MailOptions>>(),
            services.GetRequiredService<IamMetrics>(),
            services.GetRequiredService<ILogger<OutboxDispatcher>>());

    /// <summary>Starts from an empty outbox (rows of this disposable test database only) and queues new messages.</summary>
    private Task<List<Guid>> ArrangeAsync(int count)
        => Stack.InIamAsync(async services =>
        {
            var db = services.GetRequiredService<IamDbContext>();
            await db.OutboxMessages.ExecuteDeleteAsync();
            var outbox = services.GetRequiredService<MailOutbox>();
            for (var index = 0; index < count; index++)
            {
                outbox.Enqueue(new MailPayload(MailKind.ResetPassword, Guid.NewGuid(), $"outbox-{Guid.NewGuid():N}@example.test", "Test message", $"{Stack.IamOrigin}/account/reset-password?token=test"));
            }

            await db.SaveChangesAsync();
            return await db.OutboxMessages.Select(x => x.Id).ToListAsync();
        });

    private Task<OutboxMessage> RowAsync(Guid id)
        => Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().OutboxMessages.AsNoTracking().SingleAsync(x => x.Id == id));

    private MailOptions Settings => Stack.Iam.Services.GetRequiredService<IOptions<MailOptions>>().Value;

    [Fact]
    public async Task Lease_ParallelWorkers_GetEveryMessageExactlyOnce()
    {
        var ids = await ArrangeAsync(30);

        var perWorker = await Task.WhenAll(Enumerable.Range(0, 4).Select(async worker =>
        {
            await using var scope = Stack.Iam.Services.CreateAsyncScope();
            var dispatcher = Dispatcher(scope.ServiceProvider, new ScriptedSink(_ => null));
            var mine = new List<LeasedMail>();
            while (await dispatcher.LeaseAsync($"worker-{worker}", CancellationToken.None) is { Count: > 0 } batch)
            {
                mine.AddRange(batch);
            }

            return mine;
        }));

        var leases = perWorker.SelectMany(batch => batch).ToList();
        Assert.Equal(ids.Count, leases.Count);
        Assert.Equal(ids.Order(), leases.Select(lease => lease.Id).Order());
        Assert.All(leases, lease =>
        {
            Assert.Equal(1, lease.LeaseVersion);
            Assert.Equal(1, lease.Attempts);
        });
        var rows = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().OutboxMessages.AsNoTracking().ToListAsync());
        Assert.All(rows, row =>
        {
            Assert.Equal(1, row.LeaseVersion);
            Assert.StartsWith("worker-", row.LeaseOwner);
        });
    }

    [Fact]
    public async Task Lease_OfACrashedWorker_IsTakenOverAfterItExpires_AndTheOldWorkerIsFencedOut()
    {
        var id = (await ArrangeAsync(1)).Single();
        await using var scopeA = Stack.Iam.Services.CreateAsyncScope();
        await using var scopeB = Stack.Iam.Services.CreateAsyncScope();
        var crashed = Dispatcher(scopeA.ServiceProvider, new ScriptedSink(_ => null));
        var successor = Dispatcher(scopeB.ServiceProvider, new ScriptedSink(_ => null));

        var stale = Assert.Single(await crashed.LeaseAsync("worker-a", CancellationToken.None));

        // While the lease is held nobody else gets the message.
        Assert.Empty(await successor.LeaseAsync("worker-b", CancellationToken.None));
        Stack.Time.Advance(TimeSpan.FromSeconds(Settings.LeaseSeconds - 1));
        Assert.Empty(await successor.LeaseAsync("worker-b", CancellationToken.None));

        Stack.Time.Advance(TimeSpan.FromSeconds(2));
        var current = Assert.Single(await successor.LeaseAsync("worker-b", CancellationToken.None));
        Assert.Equal(stale.LeaseVersion + 1, current.LeaseVersion);
        Assert.Equal(2, current.Attempts);

        // The first worker wakes up late. Neither its success nor its failure report is accepted.
        var before = await RowAsync(id);
        Assert.False(await crashed.CompleteAsync(stale, CancellationToken.None));
        Assert.False(await crashed.FailAsync(stale, "LateFailure", CancellationToken.None));
        var after = await RowAsync(id);
        Assert.Null(after.DeliveredAt);
        Assert.Null(after.DeadAt);
        Assert.Null(after.LastErrorCode);
        Assert.Equal("worker-b", after.LeaseOwner);
        Assert.Equal(before.AvailableAt, after.AvailableAt);
        Assert.Equal(before.LeaseUntil, after.LeaseUntil);

        Assert.True(await successor.CompleteAsync(current, CancellationToken.None));
        Assert.False(await successor.CompleteAsync(current, CancellationToken.None));
        var delivered = await RowAsync(id);
        Assert.NotNull(delivered.DeliveredAt);
        Assert.Null(delivered.LeaseOwner);
    }

    [Fact]
    public async Task Delivery_ThatKeepsFailing_BacksOffExponentially_ThenIsDeadLettered()
    {
        var id = (await ArrangeAsync(1)).Single();
        var sink = new ScriptedSink(_ => new IOException("private detail C:/secret/mail-sink user@example.test"));
        var max = Settings.MaxAttempts;

        for (var attempt = 1; attempt <= max; attempt++)
        {
            var delivered = await Stack.InIamAsync(services => Dispatcher(services, sink).DispatchOnceAsync("worker", CancellationToken.None));
            var row = await RowAsync(id);
            Assert.Equal(0, delivered);
            Assert.Equal(attempt, row.Attempts);
            Assert.Equal(attempt, sink.Calls);
            Assert.Equal(nameof(IOException), row.LastErrorCode);
            Assert.Null(row.LeaseOwner);
            Assert.Null(row.DeliveredAt);
            if (attempt == max)
            {
                Assert.Equal(Stack.Time.GetUtcNow().AsStored(), row.DeadAt);
                break;
            }

            var delay = TimeSpan.FromSeconds(5 * Math.Pow(2, attempt - 1));
            Assert.Null(row.DeadAt);
            Assert.Equal((Stack.Time.GetUtcNow() + delay).AsStored(), row.AvailableAt);

            // One second before the retry time the message is left alone.
            Stack.Time.Advance(delay - TimeSpan.FromSeconds(1));
            await Stack.InIamAsync(services => Dispatcher(services, sink).DispatchOnceAsync("worker", CancellationToken.None));
            Assert.Equal(attempt, sink.Calls);
            Stack.Time.Advance(TimeSpan.FromSeconds(1));
        }

        // A dead message is never picked up again.
        Stack.Time.Advance(TimeSpan.FromHours(1));
        await Stack.InIamAsync(services => Dispatcher(services, sink).DispatchOnceAsync("worker", CancellationToken.None));
        Assert.Equal(max, sink.Calls);
        Assert.Equal(max, (await RowAsync(id)).Attempts);

        // Only the error type is kept; the message text (paths, addresses) is neither stored nor logged.
        Assert.DoesNotContain(Stack.Logs.Lines, line => line.Contains("private detail", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Delivery_RecoversWhenTheSinkComesBack_AndDeliversOnce()
    {
        var id = (await ArrangeAsync(1)).Single();
        var sink = new ScriptedSink(call => call <= 2 ? new IOException("sink offline") : null);
        Task<int> DispatchAsync() => Stack.InIamAsync(services => Dispatcher(services, sink).DispatchOnceAsync("worker", CancellationToken.None));

        Assert.Equal(0, await DispatchAsync());
        Stack.Time.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(0, await DispatchAsync());
        Stack.Time.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await DispatchAsync());

        var row = await RowAsync(id);
        Assert.NotNull(row.DeliveredAt);
        Assert.Equal(3, row.Attempts);
        Assert.Null(row.LastErrorCode);
        Assert.Equal([id], sink.Delivered);

        Stack.Time.Advance(TimeSpan.FromHours(1));
        Assert.Equal(0, await DispatchAsync());
        Assert.Equal(3, sink.Calls);
    }

    [Fact]
    public async Task Worker_DeliversQueuedMail_PicksUpNewMailOnTheNextTick_AndStopsCleanly()
    {
        var first = (await ArrangeAsync(1)).Single();
        var worker = new OutboxWorker(
            Stack.Iam.Services.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new MailOptions { WorkerEnabled = true, PollSeconds = 1 }),
            Stack.IamTime,
            Stack.Iam.Services.GetRequiredService<ILogger<OutboxWorker>>());

        await worker.StartAsync(CancellationToken.None);
        try
        {
            await Eventually.TrueAsync(async () => (await RowAsync(first)).DeliveredAt is not null, "the queued message to be delivered");

            var second = await Stack.InIamAsync(async services =>
            {
                var db = services.GetRequiredService<IamDbContext>();
                services.GetRequiredService<MailOutbox>().Enqueue(new MailPayload(MailKind.ConfirmEmail, Guid.NewGuid(), $"outbox-{Guid.NewGuid():N}@example.test", "Second", $"{Stack.IamOrigin}/account/confirm-email?token=test"));
                await db.SaveChangesAsync();
                return await db.OutboxMessages.Where(x => x.Id != first).Select(x => x.Id).SingleAsync();
            });
            await Eventually.TrueAsync(async () =>
            {
                // The worker sleeps on the application clock; each step is one poll interval.
                Stack.Time.Advance(TimeSpan.FromSeconds(1));
                return (await RowAsync(second)).DeliveredAt is not null;
            }, "the second message to be delivered on a later tick");

            // The private sink holds exactly one file per message, also when a delivery is repeated.
            var sink = Stack.Iam.Services.GetRequiredService<IMailSink>();
            await sink.DeliverAsync(second, new MailPayload(MailKind.ConfirmEmail, Guid.NewGuid(), "repeat@example.test", "Second", "https://id.halka.localhost/x"), CancellationToken.None);
            Assert.Single(Directory.GetFiles(Stack.MailSinkDirectory, $"{second:N}*"));
            Assert.Single(Directory.GetFiles(Stack.MailSinkDirectory, $"{first:N}*"));
        }
        finally
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await worker.StopAsync(limit.Token);
        }

        Assert.True(worker.ExecuteTask!.IsCompletedSuccessfully);
    }
}
