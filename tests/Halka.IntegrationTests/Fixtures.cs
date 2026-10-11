namespace Halka.IntegrationTests;

public class StackFixture : IAsyncLifetime
{
    public HalkaStack Stack { get; private set; } = null!;

    protected virtual StackOptions Options => new();

    public async ValueTask InitializeAsync() => Stack = await HalkaStack.StartAsync(Options);

    public async ValueTask DisposeAsync()
    {
        await Stack.DisposeAsync();
        GC.SuppressFinalize(this);
    }
}

/// <summary>Main stack shared by tests that do not move the clock by more than a few minutes.</summary>
[CollectionDefinition(Name)]
public sealed class StackCollection : ICollectionFixture<StackFixture>
{
    public const string Name = "stack";
}

/// <summary>Separate stack for tests that advance the fake clock by hours (expiry, idle and absolute timeouts).</summary>
[CollectionDefinition(Name)]
public sealed class TimeTravelCollection : ICollectionFixture<StackFixture>
{
    public const string Name = "time-travel";
}

public static class TestCategories
{
    public const string Trait = "Category";
    public const string Protocol = "Protocol";
    public const string Security = "Security";
    public const string Database = "Database";
}
