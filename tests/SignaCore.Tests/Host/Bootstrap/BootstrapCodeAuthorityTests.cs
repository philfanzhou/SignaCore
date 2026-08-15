using SignaCore.Host.Bootstrap;
using Xunit;

namespace SignaCore.Tests.Host.Bootstrap;

public sealed class BootstrapCodeAuthorityTests
{
    [Fact]
    public void Verify_AcceptsTheGeneratedCodeOnlyUntilItExpires()
    {
        var clock = new StubTimeProvider(new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero));
        var authority = BootstrapCodeAuthority.Create(out var code, clock);

        Assert.True(authority.Verify(code));

        clock.UtcNow = authority.ExpiresAt;

        Assert.False(authority.Verify(code));
    }

    [Fact]
    public void Consume_InvalidatesAnOtherwiseValidCode()
    {
        var authority = BootstrapCodeAuthority.Create(out var code);

        authority.Consume();

        Assert.True(authority.IsConsumed);
        Assert.False(authority.Verify(code));
    }

    [Fact]
    public async Task SaveLease_SerializesConcurrentCodeVerificationAndConsumption()
    {
        var authority = BootstrapCodeAuthority.Create(out var code);
        using var first = await authority.AcquireSaveLeaseAsync(CancellationToken.None);

        var waiting = authority.AcquireSaveLeaseAsync(CancellationToken.None).AsTask();
        Assert.False(waiting.IsCompleted);

        authority.Consume();
        first.Dispose();
        using var second = await waiting;

        Assert.False(authority.Verify(code));
    }

    private sealed class StubTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
