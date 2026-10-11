using Halka.Iam.Identity;
using Halka.Iam.Ops;
using Halka.Iam.Sessions;
using Microsoft.Extensions.Options;

namespace Halka.UnitTests;

public sealed class SessionModelTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    private static CurrentSession Session(bool mfaEnabled, TimeSpan passwordAge, TimeSpan? mfaAge, params string[] amr)
        => new(Guid.NewGuid(), Guid.NewGuid(), "user@example.test", "User", Now - passwordAge, amr, Now - passwordAge,
            mfaAge is null ? null : Now - mfaAge, Now.AddHours(1), [Roles.User], mfaEnabled);

    [Fact]
    public void StepUp_WithoutMfa_RequiresRecentPassword()
    {
        Assert.True(Session(false, TimeSpan.FromMinutes(4), null, Amr.Password).IsStepUpFresh(Now, Window));
        Assert.False(Session(false, TimeSpan.FromMinutes(6), null, Amr.Password).IsStepUpFresh(Now, Window));
    }

    [Fact]
    public void StepUp_WithMfa_RequiresRecentSecondFactor_RecentPasswordAloneIsNotEnough()
    {
        Assert.False(Session(true, TimeSpan.FromMinutes(1), null, Amr.Password).IsStepUpFresh(Now, Window));
        Assert.False(Session(true, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(6), Amr.Password, Amr.Otp, Amr.Mfa).IsStepUpFresh(Now, Window));
        Assert.True(Session(true, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(2), Amr.Password, Amr.Otp, Amr.Mfa).IsStepUpFresh(Now, Window));
    }

    [Fact]
    public void Amr_JoinAndSplit_RoundTripWithoutDuplicates()
    {
        var joined = Amr.Join([Amr.Password, Amr.Otp, Amr.Mfa, Amr.Password]);

        Assert.Equal("pwd otp mfa", joined);
        Assert.Equal([Amr.Password, Amr.Otp, Amr.Mfa], Amr.Split(joined));
        Assert.Empty(Amr.Split(string.Empty));
    }

    [Fact]
    public void HasMfa_ReflectsOnlyWhatTheSessionActuallyPerformed()
    {
        Assert.False(Session(true, TimeSpan.Zero, null, Amr.Password).HasMfa);
        Assert.True(Session(true, TimeSpan.Zero, TimeSpan.Zero, Amr.Password, Amr.Mfa).HasMfa);
    }

    [Theory]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", "Chrome on Windows")]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0", "Edge on Windows")]
    [InlineData("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", "Safari on macOS")]
    [InlineData("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "Firefox on Linux")]
    [InlineData("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36", "Chrome on Android")]
    [InlineData("curl/8.9.1", "Other browser on other platform")]
    [InlineData("", "Unknown client")]
    [InlineData(null, "Unknown client")]
    public void ClientLabel_IsCoarse(string? userAgent, string expected)
        => Assert.Equal(expected, ClientLabel.FromUserAgent(userAgent));

    [Fact]
    public void TicketPrincipal_CarriesOnlySubjectAndSessionIdentifiers()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var principal = SessionPrincipal.ForTicket(userId, sessionId);

        Assert.Equal(2, principal.Claims.Count());
        Assert.True(SessionPrincipal.TryRead(principal, out var readUser, out var readSession));
        Assert.Equal(userId, readUser);
        Assert.Equal(sessionId, readSession);
        Assert.False(principal.IsInRole(Roles.PlatformAdmin));
    }

    [Fact]
    public void AccountAttemptLimiter_LimitsPerAddressAndAccount_WithoutSharingABucket()
    {
        using var limiter = new AccountAttemptLimiter(Options.Create(new RateLimitOptions { LoginPerAccountPerMinute = 3 }));

        Assert.True(limiter.TryAcquire("203.0.113.5", "A@EXAMPLE.TEST"));
        Assert.True(limiter.TryAcquire("203.0.113.5", "A@EXAMPLE.TEST"));
        Assert.True(limiter.TryAcquire("203.0.113.5", "A@EXAMPLE.TEST"));
        Assert.False(limiter.TryAcquire("203.0.113.5", "A@EXAMPLE.TEST"));

        // Another account from the same address and the same account from another address are unaffected.
        Assert.True(limiter.TryAcquire("203.0.113.5", "B@EXAMPLE.TEST"));
        Assert.True(limiter.TryAcquire("203.0.113.9", "A@EXAMPLE.TEST"));
    }
}
