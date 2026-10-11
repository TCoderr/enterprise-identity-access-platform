using Halka.Iam.Data;
using Halka.Iam.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Halka.IntegrationTests.Stage1;

[Collection(TimeTravelCollection.Name)]
[Trait(TestCategories.Trait, TestCategories.Security)]
public sealed class SessionTimeoutTests(StackFixture fixture)
{
    private HalkaStack Stack => fixture.Stack;

    [Fact]
    public async Task Session_IdleTimeout_EndsTheSessionAndRecordsTheReason()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, user);

        Stack.Time.Advance(TimeSpan.FromMinutes(59));
        Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        // Activity above moved the idle window; a full idle period without requests ends the session.
        Stack.Time.Advance(TimeSpan.FromMinutes(61));
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        var session = await Stack.InIamAsync(services => services.GetRequiredService<IamDbContext>().UserSessions.SingleAsync(x => x.UserId == user.Id));
        Assert.NotNull(session.RevokedAt);
        Assert.Equal(SessionEndReason.IdleTimeout, session.RevokedReason);
    }

    [Fact]
    public async Task Session_AbsoluteLifetime_CannotBeExtendedByActivity()
    {
        var user = await Stack.CreateUserAsync();
        using var browser = Stack.NewBrowser();
        await Stack.SignInAsync(browser, user);

        // Stay active every 45 minutes up to 11 h 15 min; the next step crosses the 12 hour absolute limit.
        for (var elapsed = TimeSpan.Zero; elapsed < TimeSpan.FromHours(11); elapsed += TimeSpan.FromMinutes(45))
        {
            Stack.Time.Advance(TimeSpan.FromMinutes(45));
            Assert.Equal("/manage", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);
        }

        Stack.Time.Advance(TimeSpan.FromMinutes(45));
        Assert.Equal("/account/login", (await browser.GetAsync($"{Stack.IamOrigin}/manage")).Url.AbsolutePath);

        var active = await Stack.InIamAsync(services => services.GetRequiredService<SessionService>()
            .Active(Stack.Time.GetUtcNow()).CountAsync(x => x.UserId == user.Id));
        Assert.Equal(0, active);
    }
}
