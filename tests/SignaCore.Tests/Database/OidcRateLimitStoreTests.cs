using SignaCore.Database;
using SignaCore.Database.RateLimiting;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Database;

public class OidcRateLimitStoreTests
{
    private const string ValidDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Port 1 on the loopback address: any connection attempt would fail. Validation must reject
    // the inputs below before one is made, so they surface as ArgumentException, never Unavailable.
    private static DatabaseOptions UnreachablePostgreSql() => new()
    {
        Provider = "PostgreSQL",
        ServerVersion = "15",
        ConnectionString = "Host=127.0.0.1;Port=1;Database=rate_limit_unit;Username=unit;Password=unit-canary-password;Timeout=1"
    };

    [Fact]
    public void Budgets_MatchTheHostPoliciesAndTheirFixedLimits()
    {
        Assert.Equal(
            OidcRateLimitPolicies.All.Order(StringComparer.Ordinal),
            OidcRateLimitBudgets.Policies.Order(StringComparer.Ordinal));
        foreach (var policy in OidcRateLimitPolicies.All)
        {
            Assert.True(OidcRateLimitBudgets.TryGetPermitLimit(policy, out var limit));
            Assert.Equal(90, limit);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")]
    [InlineData("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdeg0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd f")]
    [InlineData("０123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public async Task AcquireAsync_RejectsNonCanonicalDigestsWithoutEchoingThem(string? digest)
    {
        await using var store = new PostgreSqlOidcRateLimitStore(UnreachablePostgreSql());

        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => store.AcquireAsync(OidcRateLimitPolicies.Token, digest!, TestContext.Current.CancellationToken));

        Assert.Equal("partitionDigest", exception.ParamName);
        if (!string.IsNullOrEmpty(digest)) Assert.DoesNotContain(digest, exception.Message);
        Assert.False(OidcRateLimitBudgets.IsPartitionDigest(digest));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("oidc-TOKEN")]
    [InlineData("oidc-token ")]
    [InlineData("oidc-unknown-canary")]
    public async Task AcquireAsync_RejectsUnknownPoliciesWithoutEchoingThem(string? policy)
    {
        await using var store = new PostgreSqlOidcRateLimitStore(UnreachablePostgreSql());

        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => store.AcquireAsync(policy!, ValidDigest, TestContext.Current.CancellationToken));

        Assert.Equal("policy", exception.ParamName);
        Assert.DoesNotContain("canary", exception.Message);
    }

    [Fact]
    public async Task AcquireAsync_UnreachableDatabaseIsUnavailableAndPreCanceledCallerWins()
    {
        await using var store = new PostgreSqlOidcRateLimitStore(UnreachablePostgreSql());

        Assert.Equal(
            OidcRateLimitAcquireResult.Unavailable,
            await store.AcquireAsync(OidcRateLimitPolicies.Token, ValidDigest, TestContext.Current.CancellationToken));
        Assert.Null(await store.DeleteExpiredAsync(TestContext.Current.CancellationToken));

        using var caller = new CancellationTokenSource();
        caller.Cancel();
        var canceled = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => store.AcquireAsync(OidcRateLimitPolicies.Token, ValidDigest, caller.Token));
        Assert.Equal(caller.Token, canceled.CancellationToken);
        canceled = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.DeleteExpiredAsync(caller.Token));
        Assert.Equal(caller.Token, canceled.CancellationToken);
    }

    [Fact]
    public void Constructor_RequiresPostgreSql()
    {
        var sqlite = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={Path.Combine(Path.GetTempPath(), "rate-limit-unit.db")}"
        };

        var exception = Assert.Throws<InvalidOperationException>(() => new PostgreSqlOidcRateLimitStore(sqlite));
        Assert.DoesNotContain("rate-limit-unit", exception.Message);
        Assert.Throws<ArgumentNullException>(() => new PostgreSqlOidcRateLimitStore(null!));
    }
}
