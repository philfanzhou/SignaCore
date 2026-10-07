extern alias ConsumerApp;

using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

public sealed class ClientPreSignInAuthorizationTests
{
    public static TheoryData<FakeIdentityProvider.AccessDefect> InvalidAccessTokens =>
        new(Enum.GetValues<FakeIdentityProvider.AccessDefect>().Where(value => value != FakeIdentityProvider.AccessDefect.None));

    [Theory]
    [MemberData(nameof(InvalidAccessTokens))]
    public async Task InvalidAccessTokens_NeverCallTheDecisionOrWriteATicket(FakeIdentityProvider.AccessDefect defect)
    {
        await using var harness = await Harness.CreateAsync();
        harness.Authority.AccessTokenDefect = defect;
        using var response = await harness.CallbackAsync(await harness.BeginAsync());
        AssertFailure(response, "invalid_token");
        Assert.Equal(0, harness.Decision.Calls);
        Assert.Equal(0, harness.Store.Writes);
    }

    [Fact]
    public async Task Allowed_UsesIndependentVerifiedClaims_AndPreservesCookieAndReturnUrl()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Decision.Run = (context, _) =>
        {
            Assert.Equal(FakeIdentityProvider.BaseAddress, context.Issuer);
            Assert.Equal(FakeIdentityProvider.DefaultSubject, context.Subject);
            Assert.Equal("reader", context.AccessTokenPrincipal.FindFirst("role")?.Value);
            Assert.Null(context.IdTokenPrincipal.FindFirst("role"));
            Assert.Equal(context.Subject, context.IdTokenPrincipal.FindFirst("sub")?.Value);
            ((ClaimsIdentity)context.IdTokenPrincipal.Identity!).AddClaim(new Claim("role", "injected"));
            return ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
        };
        using var response = await harness.CallbackAsync(await harness.BeginAsync());
        Assert.Equal("/dashboard", response.Headers.Location?.ToString());
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        foreach (var attribute in new[] { "httponly", "secure", "samesite=lax", "path=/" })
            Assert.Contains(attribute, cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, harness.Decision.Calls);
        Assert.Equal(1, harness.Store.Writes);
        Assert.Null(harness.Store.LastTicket!.Principal.FindFirst("role"));
        Assert.True(harness.Store.LastTicket.ExpiresUtc <= harness.Clock.GetUtcNow().AddMinutes(15));
    }

    [Theory]
    [InlineData("denied")]
    [InlineData("unknown")]
    [InlineData("sync")]
    [InlineData("async")]
    [InlineData("cancel")]
    public async Task DecisionFailures_KeepAnExistingSessionUnchanged(string failure)
    {
        var capture = new CapturingLoggerProvider();
        await using var harness = await Harness.CreateAsync(capture);
        using var allowed = await harness.CallbackAsync(await harness.BeginAsync());
        var existing = harness.Browser.Cookies.GetCookieHeader(harness.Browser.ConsumerBase);
        var original = harness.Store.LastTicket;
        harness.Decision.Run = (_, _) => failure switch
        {
            "denied" => ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Denied),
            "unknown" => ValueTask.FromResult((SignaCoreAuthorizationDecisionResult)99),
            "sync" => throw new InvalidOperationException("private-decision-detail"),
            "async" => new ValueTask<SignaCoreAuthorizationDecisionResult>(Task.FromException<SignaCoreAuthorizationDecisionResult>(new InvalidOperationException("private-decision-detail"))),
            _ => throw new OperationCanceledException("private-decision-detail")
        };
        using var response = await harness.CallbackAsync(await harness.BeginAsync());
        AssertFailure(response, "pre_sign_in_denied");
        Assert.Equal(existing, harness.Browser.Cookies.GetCookieHeader(harness.Browser.ConsumerBase));
        Assert.Same(original, harness.Store.LastTicket);
        Assert.Equal(1, harness.Store.Writes);
        Assert.DoesNotContain(capture.Lines, line => line.Contains("private-decision-detail", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Timeout_CancelsConsumerToken_AndLateCompletionCannotSignIn(bool lateFault)
    {
        await using var harness = await Harness.CreateAsync();
        var entered = Signal();
        var late = new TaskCompletionSource<SignaCoreAuthorizationDecisionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken decisionToken = default;
        harness.Decision.Run = (_, token) => { decisionToken = token; entered.SetResult(); return new(late.Task); };
        var callback = harness.CallbackAsync(await harness.BeginAsync());
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await harness.Clock.TimerCreated.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        harness.Clock.Advance(TimeSpan.FromSeconds(11));
        using var response = await callback;
        AssertFailure(response, "pre_sign_in_denied");
        Assert.True(decisionToken.IsCancellationRequested);
        if (lateFault) late.SetException(new InvalidOperationException("private-late-detail"));
        else late.SetResult(SignaCoreAuthorizationDecisionResult.Allowed);
        Assert.Equal(0, harness.Store.Writes);
        using var replay = await harness.CallbackAsync(response.RequestMessage!.RequestUri!.ToString());
        AssertFailure(replay, "state_mismatch");
        Assert.Single(harness.Authority.RedeemedCodes);
    }

    [Fact]
    public async Task CancellationBeforeDecision_PropagatesAndNeverWrites()
    {
        await using var harness = await Harness.CreateAsync();
        var url = await harness.BeginAsync();
        var tokenGate = harness.Authority.HoldTokenRequests();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        // The request-specific token is the cancellation behavior under test.
#pragma warning disable xUnit1051
        var callback = harness.CallbackWithCancellationAsync(url, cancellation.Token);
#pragma warning restore xUnit1051
        await harness.Authority.TokenArrived.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => callback);
        tokenGate.SetResult();
        Assert.Equal(0, harness.Decision.Calls);
        Assert.Equal(0, harness.Store.Writes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RequestCancellation_DuringDecisionOrAfterAllowed_PropagatesWithoutWrites(bool afterAllowed)
    {
        await using var harness = await Harness.CreateAsync();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var entered = Signal();
        var late = new TaskCompletionSource<SignaCoreAuthorizationDecisionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Decision.Run = (_, _) =>
        {
            entered.SetResult();
            if (afterAllowed) { cancellation.Cancel(); return ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed); }
            return new(late.Task);
        };
        // The request-specific token is the cancellation behavior under test.
#pragma warning disable xUnit1051
        var callback = harness.CallbackWithCancellationAsync(await harness.BeginAsync(), cancellation.Token);
#pragma warning restore xUnit1051
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        if (!afterAllowed) await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => callback);
        late.TrySetResult(SignaCoreAuthorizationDecisionResult.Allowed);
        Assert.Equal(0, harness.Store.Writes);
        Assert.Equal(string.Empty, harness.Browser.Cookies.GetCookieHeader(harness.Browser.ConsumerBase));
    }

    [Fact]
    public async Task ActualExpiryDuringDecision_Fails_AndWaitTimeNeverExtendsTicketLifetime()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Authority.AccessLifetime = TimeSpan.FromSeconds(5);
        harness.Decision.Run = (_, _) =>
        {
            harness.Clock.Advance(TimeSpan.FromSeconds(6));
            return ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
        };
        using var expired = await harness.CallbackAsync(await harness.BeginAsync());
        AssertFailure(expired, "invalid_token");
        Assert.Equal(0, harness.Store.Writes);

        harness.Authority.AccessLifetime = TimeSpan.FromMinutes(30);
        var before = harness.Clock.GetUtcNow();
        harness.Decision.Run = (_, _) =>
        {
            harness.Clock.Advance(TimeSpan.FromSeconds(5));
            return ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
        };
        using var allowed = await harness.CallbackAsync(await harness.BeginAsync());
        Assert.Equal("/dashboard", allowed.Headers.Location?.ToString());
        Assert.Equal(before.AddSeconds(900), harness.Store.LastTicket!.ExpiresUtc);
        Assert.Equal(before, harness.Store.LastTicket.IssuedUtc);
    }

    [Fact]
    public async Task OnePendingCallback_HasOnlyOneExchangeDecisionAndWrite()
    {
        await using var harness = await Harness.CreateAsync();
        var entered = Signal();
        var gate = new TaskCompletionSource<SignaCoreAuthorizationDecisionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Decision.Run = (_, _) => { entered.SetResult(); return new(gate.Task); };
        var url = await harness.BeginAsync();
        var first = harness.CallbackAsync(url);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        using var second = await harness.CallbackAsync(url);
        AssertFailure(second, "state_mismatch");
        gate.SetResult(SignaCoreAuthorizationDecisionResult.Allowed);
        using var winner = await first;
        Assert.Equal("/dashboard", winner.Headers.Location?.ToString());
        Assert.Single(harness.Authority.RedeemedCodes);
        Assert.Equal(1, harness.Decision.Calls);
        Assert.Equal(1, harness.Store.Writes);
    }

    [Fact]
    public async Task IndependentCallbacks_HaveIndependentPrincipalCopiesAndDecisions()
    {
        await using var harness = await Harness.CreateAsync();
        var entered = Signal();
        var release = Signal();
        ClaimsPrincipal? firstPrincipal = null;
        harness.Decision.Run = async (context, _) =>
        {
            if (Interlocked.CompareExchange(ref firstPrincipal, context.AccessTokenPrincipal, null) is null)
            {
                ((ClaimsIdentity)context.AccessTokenPrincipal.Identity!).AddClaim(new Claim("request-only", "first"));
                entered.SetResult();
                await release.Task;
                return SignaCoreAuthorizationDecisionResult.Denied;
            }
            Assert.NotSame(firstPrincipal, context.AccessTokenPrincipal);
            Assert.Null(context.AccessTokenPrincipal.FindFirst("request-only"));
            return SignaCoreAuthorizationDecisionResult.Allowed;
        };
        var firstUrl = await harness.BeginAsync();
        var secondUrl = await harness.BeginAsync();
        var first = harness.CallbackAsync(firstUrl);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        using var second = await harness.CallbackAsync(secondUrl);
        Assert.Equal("/dashboard", second.Headers.Location?.ToString());
        release.SetResult();
        using var denied = await first;
        AssertFailure(denied, "pre_sign_in_denied");
        Assert.Equal(2, harness.Authority.RedeemedCodes.Count);
        Assert.Equal(2, harness.Decision.Calls);
        Assert.Equal(1, harness.Store.Writes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(30)]
    public async Task PublishedRotatedKey_AndAllowedClockSkew_AreAccepted(int offsetSeconds)
    {
        await using var harness = await Harness.CreateAsync();
        harness.Authority.RotateSigningKey();
        harness.Authority.AccessTimeOffset = TimeSpan.FromSeconds(offsetSeconds);
        var expectedTime = harness.Clock.GetUtcNow().AddSeconds(offsetSeconds).ToUnixTimeSeconds();
        harness.Decision.Run = (context, _) =>
        {
            Assert.Equal(expectedTime.ToString(System.Globalization.CultureInfo.InvariantCulture), context.AccessTokenPrincipal.FindFirst("nbf")?.Value);
            Assert.Equal(expectedTime.ToString(System.Globalization.CultureInfo.InvariantCulture), context.AccessTokenPrincipal.FindFirst("iat")?.Value);
            return ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
        };
        using var response = await harness.CallbackAsync(await harness.BeginAsync());
        Assert.Equal("/dashboard", response.Headers.Location?.ToString());
        Assert.Equal(1, harness.Decision.Calls);
        Assert.Equal(1, harness.Store.Writes);
    }

    [Fact]
    public async Task ClockSkewBeyondThirtySeconds_IsRejectedBeforeDecision()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Authority.RotateSigningKey();
        harness.Authority.AccessTimeOffset = TimeSpan.FromSeconds(31);
        using var response = await harness.CallbackAsync(await harness.BeginAsync());
        AssertFailure(response, "invalid_token");
        Assert.Equal(0, harness.Decision.Calls);
        Assert.Equal(0, harness.Store.Writes);
    }

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static void AssertFailure(HttpResponseMessage response, string reason)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/auth/signin-failed?reason=" + reason, response.Headers.Location?.ToString());
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    private sealed class Decision : ISignaCorePreSignInAuthorizationDecision
    {
        private int _calls;
        public int Calls => _calls;
        public Func<SignaCorePreSignInAuthorizationContext, CancellationToken, ValueTask<SignaCoreAuthorizationDecisionResult>> Run { get; set; }
            = (_, _) => ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
        public ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(SignaCorePreSignInAuthorizationContext context, CancellationToken token)
        { Interlocked.Increment(ref _calls); return Run(context, token); }
    }

    private sealed class RecordingStore(TimeProvider clock) : ITicketStore
    {
        private readonly InMemoryTicketStore _inner = new(clock);
        public int Writes { get; private set; }
        public SignaCoreSessionTicket? LastTicket { get; private set; }
        public Task<string?> StoreAsync(SignaCoreSessionTicket ticket, CancellationToken token)
        { Writes++; LastTicket = ticket; return _inner.StoreAsync(ticket, token); }
        public Task<SignaCoreSessionTicket?> RetrieveAsync(string key, CancellationToken token) => _inner.RetrieveAsync(key, token);
        public Task RemoveAsync(string key, CancellationToken token) => _inner.RemoveAsync(key, token);
        public int RemoveExpired(CancellationToken token) => _inner.RemoveExpired(token);
    }

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        private readonly List<TestTimer> _timers = [];
        public TaskCompletionSource TimerCreated { get; } = Signal();
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration)
        {
            _now += duration;
            foreach (var timer in _timers.ToArray()) timer.Fire(_now);
        }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new TestTimer(callback, state, this, dueTime);
            _timers.Add(timer); TimerCreated.TrySetResult(); return timer;
        }
        private sealed class TestTimer(TimerCallback callback, object? state, Clock clock, TimeSpan dueTime) : ITimer
        {
            private DateTimeOffset _due = clock.GetUtcNow() + dueTime;
            private bool _disposed;
            public bool Change(TimeSpan due, TimeSpan period) { _due = clock.GetUtcNow() + due; return !_disposed; }
            public void Fire(DateTimeOffset now) { if (!_disposed && now >= _due) { _disposed = true; callback(state); } }
            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    private sealed class Harness : IAsyncDisposable
    {
        public required FakeIdentityProvider Authority { get; init; }
        public required WebApplicationFactory<ConsumerApp.Program> Consumer { get; init; }
        public required CrossServerBrowser Browser { get; init; }
        public required Decision Decision { get; init; }
        public required RecordingStore Store { get; init; }
        public required Clock Clock { get; init; }
        public static async Task<Harness> CreateAsync(CapturingLoggerProvider? capture = null)
        {
            var clock = new Clock(); var decision = new Decision(); var store = new RecordingStore(clock);
            var authority = await FakeIdentityProvider.StartAsync(clock);
            authority.SignedAccessToken = true;
            var consumer = ConsumerAppTestServer.Create(FakeIdentityProvider.BaseAddress,
                SignaCoreHostFixture.ClientId, SignaCoreHostFixture.ClientSecret,
                SignaCoreHostFixture.RedirectUri, authority.Server.CreateHandler(), timeProvider: clock,
                loggerProvider: capture, configureTestServices: services =>
                {
                    services.AddSingleton<ITicketStore>(store);
                    services.PostConfigure<SignaCoreHostedLoginOptions>(options => options.PreSignInAuthorizationDecision = decision);
                });
            return new Harness { Authority = authority, Consumer = consumer,
                Browser = ConsumerAppTestServer.CreateBrowserOverAuthority(consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress)),
                Decision = decision, Store = store, Clock = clock };
        }
        public async Task<string> BeginAsync()
        {
            using var start = await Browser.SendOnConsumerAsync(new(HttpMethod.Get, new Uri(Browser.ConsumerBase, "/auth/start?returnUrl=/dashboard")), TestContext.Current.CancellationToken);
            using var authorize = await Browser.SendOnIdentityServerAsync(new(HttpMethod.Get, start.Headers.Location!), TestContext.Current.CancellationToken);
            return authorize.Headers.Location!.ToString();
        }
        public Task<HttpResponseMessage> CallbackAsync(string url) => CallbackWithCancellationAsync(url, TestContext.Current.CancellationToken);
        public Task<HttpResponseMessage> CallbackWithCancellationAsync(string url, CancellationToken token) =>
            Browser.SendOnConsumerAsync(new(HttpMethod.Get, new Uri(url)), token == default ? TestContext.Current.CancellationToken : token);
        public async ValueTask DisposeAsync() { Browser.Dispose(); await Consumer.DisposeAsync(); await Authority.DisposeAsync(); }
    }
}
