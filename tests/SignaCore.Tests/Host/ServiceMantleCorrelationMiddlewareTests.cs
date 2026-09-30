using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using SignaCore.Host.Http;
using SignaCore.Host;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// The request correlation contract of the shared ServiceMantle correlation middleware, driven
/// through the same public registration the production hosts use. The authoritative rows: a single
/// value matching <c>[A-Za-z0-9][A-Za-z0-9._-]{0,63}</c> is preserved verbatim across the response
/// header, the ILogger scope, and <see cref="HttpContextExtensions.GetCorrelationId"/>; everything
/// else — missing, blank, overlong, illegal, comma-joined, or repeated headers — is discarded as a
/// whole and replaced by a generated 32-character lowercase hex id. The rejected raw value never
/// reaches any of those outputs.
/// </summary>
public partial class ServiceMantleCorrelationMiddlewareTests
{
    private const string HeaderName = ServiceMantle.Web.Http.ServiceHeaderNames.CorrelationId;

    [GeneratedRegex("^[0-9a-f]{32}$")]
    private static partial Regex GeneratedIdPattern();

    private sealed record CapturedScope(IReadOnlyList<KeyValuePair<string, object?>> Fields);

    /// <summary>
    /// Records BeginScope states pushed on any logger, and every log entry written, so the tests can
    /// pin both what the scope carried and that the middleware itself logs nothing.
    /// </summary>
    private sealed class CaptureProvider : ILoggerProvider
    {
        private readonly ConcurrentDictionary<string, CapturedScope?> _activeScopes = new();
        public ConcurrentQueue<CapturedScope> OpenedScopes { get; } = new();
        public ConcurrentQueue<string> LogEntries { get; } = new();
        public int ActiveScopeCount => _activeScopes.Count;

        public ILogger CreateLogger(string categoryName) => new CaptureLogger(this);

        public void Dispose()
        {
        }

        private sealed class CaptureLogger(CaptureProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                if (state is IReadOnlyList<KeyValuePair<string, object?>> fields)
                {
                    var captured = new CapturedScope(fields);
                    owner.OpenedScopes.Enqueue(captured);
                    var scope = new CaptureScope(owner);
                    owner._activeScopes[scope.Id] = captured;
                    return scope;
                }

                return NullScope.Instance;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.LogEntries.Enqueue(formatter(state, exception));
        }

        private sealed class CaptureScope(CaptureProvider owner) : IDisposable
        {
            public string Id { get; } = Guid.NewGuid().ToString("N");

            public void Dispose() => owner._activeScopes.TryRemove(Id, out _);
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }


    /// <summary>
    /// Records the OnStarting callbacks the middleware registers and replays them the way a real
    /// server does when the response starts. DefaultHttpContext's StartAsync is a no-op, so without
    /// this the write-back path would never run in-process.
    /// </summary>
    private sealed class ResponseStartFeature(IHttpResponseFeature inner) : IHttpResponseFeature
    {
        private readonly List<(Func<object, Task> Callback, object State)> onStarting = [];

        public Stream Body { get => inner.Body; set => inner.Body = value; }
        public IHeaderDictionary Headers { get => inner.Headers; set => inner.Headers = value; }
        public bool HasStarted => inner.HasStarted;
        public string? ReasonPhrase { get => inner.ReasonPhrase; set => inner.ReasonPhrase = value; }
        public int StatusCode { get => inner.StatusCode; set => inner.StatusCode = value; }

        public void OnStarting(Func<object, Task> callback, object state) =>
            onStarting.Add((callback, state));

        public void OnCompleted(Func<object, Task> callback, object state) =>
            inner.OnCompleted(callback, state);

        public async Task StartResponseAsync()
        {
            foreach (var (callback, state) in onStarting)
            {
                await callback(state);
            }
        }
    }

    private static async Task<DefaultHttpContext> InvokeAsync(
        RequestDelegate downstream,
        CaptureProvider? capture = null,
        Action<HttpRequest>? prepareRequest = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging =>
        {
            if (capture is not null)
            {
                logging.AddProvider(capture);
            }
        });
        services.AddSignaCoreServiceMantle();
        var provider = services.BuildServiceProvider();

        var app = new ApplicationBuilder(provider);
        app.UseServiceMantleCorrelationId();
        app.Run(downstream);
        var pipeline = app.Build();

        var context = new DefaultHttpContext();
        context.Features.Set<IHttpResponseFeature>(
            new ResponseStartFeature(context.Features.Get<IHttpResponseFeature>()!));
        prepareRequest?.Invoke(context.Request);
        await pipeline(context);
        return context;
    }


    private static Task StartResponseAsync(HttpContext context) =>
        (context.Features.Get<IHttpResponseFeature>() as ResponseStartFeature)!.StartResponseAsync();

    private static string? ScopeField(CapturedScope scope, string name)
    {
        foreach (var field in scope.Fields)
        {
            if (string.Equals(field.Key, name, StringComparison.Ordinal))
            {
                return field.Value?.ToString();
            }
        }

        return null;
    }

    // ---- Accepted shape: preserved verbatim across every output ----

    [Theory]
    [InlineData("a")]
    [InlineData("A0-z.9_x-Y")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    public async Task AcceptedValue_IsPreservedAcrossSlotScopeAndResponse(string value)
    {
        var capture = new CaptureProvider();

        var context = await InvokeAsync(
            _ => Task.CompletedTask,
            capture,
            request => request.Headers[HeaderName] = value);

        Assert.Equal(value, context.GetCorrelationId());
        var scope = Assert.Single(capture.OpenedScopes);
        Assert.Equal(value, ScopeField(scope, "CorrelationId"));
        // The identity fields the library adds to its request scope are present alongside.
        Assert.Equal("signacore", ScopeField(scope, "ServiceName"));
        await StartResponseAsync(context);
        Assert.Equal(value, context.Response.Headers[HeaderName]);
        Assert.Empty(capture.LogEntries);
    }

    [Fact]
    public async Task SixtyFourCharacterValue_IsAcceptedAtTheUpperBound()
    {
        // First character alphanumeric, the remaining 63 from the accepted tail set.
        var value = "a" + new string('x', 62) + "_";
        Assert.Equal(64, value.Length);

        var context = await InvokeAsync(
            _ => Task.CompletedTask,
            prepareRequest: request => request.Headers[HeaderName] = value);

        Assert.Equal(value, context.GetCorrelationId());
    }

    // ---- Rejected shapes: whole-input rejection with a generated id ----

    public static TheoryData<string> RejectedSingleValues => new()
    {
        "",          // empty
        "   ",       // whitespace
        "a b",       // embedded space
        "ab\x007fc", // control character
        "ab\u00e9c", // non-ASCII letter
        "a,b",       // comma-joined single header value
        "-abc",      // leading punctuation
        ".abc",      // leading dot
        "_abc",      // leading underscore
        "abc!",      // illegal trailing character
        "abc/def",   // path fragment
    };

    [Theory]
    [MemberData(nameof(RejectedSingleValues))]
    public async Task RejectedSingleValue_IsDiscardedWholeAndReplacedByGeneratedId(string value)
    {
        var capture = new CaptureProvider();

        var context = await InvokeAsync(
            _ => Task.CompletedTask,
            capture,
            request => request.Headers[HeaderName] = value);

        await AssertGeneratedOutputsAsync(context, capture, value);
    }

    [Fact]
    public async Task SixtyFiveCharacterValue_IsRejected()
    {
        var value = "a" + new string('x', 63) + "y";
        Assert.Equal(65, value.Length);

        var context = await InvokeAsync(
            _ => Task.CompletedTask,
            prepareRequest: request => request.Headers[HeaderName] = value);

        var correlationId = context.GetCorrelationId();
        Assert.Matches(GeneratedIdPattern(), correlationId);
        Assert.NotEqual(value, correlationId);
    }

    [Fact]
    public async Task MissingHeader_GeneratesId()
    {
        var capture = new CaptureProvider();

        var context = await InvokeAsync(_ => Task.CompletedTask, capture);

        await AssertGeneratedOutputsAsync(context, capture, null);
    }

    [Theory]
    [InlineData("same-value")]
    [InlineData("first-value")]
    public async Task RepeatedHeader_RegardlessOfEquality_IsDiscardedWhole(string secondValue)
    {
        var capture = new CaptureProvider();

        var context = await InvokeAsync(
            _ => Task.CompletedTask,
            capture,
            request => request.Headers[HeaderName] = new StringValues(["same-value", secondValue]));

        // Neither the first nor any other entry is selected or truncated.
        await AssertGeneratedOutputsAsync(context, capture, "same-value");
    }

    [Theory]
    [InlineData("abc\rWARN forged")]
    [InlineData("abc\nWARN forged")]
    [InlineData("abc\r\nWARN forged")]
    [InlineData("abc\u2028WARN forged")]
    [InlineData("abc\u2029WARN forged")]
    public async Task LineBreakValue_IsRejectedEntirely_InProcessFixture(string value)
    {
        var capture = new CaptureProvider();

        var context = await InvokeAsync(
            _ => Task.CompletedTask,
            capture,
            request => request.Headers[HeaderName] = value);

        // The in-process fixture sets what the HTTP parser would never deliver; the middleware
        // still rejects the value as a whole, so the forged content cannot reach any output.
        await AssertGeneratedOutputsAsync(context, capture, value);
        foreach (var entry in capture.LogEntries)
        {
            Assert.DoesNotContain("forged", entry, StringComparison.Ordinal);
        }
    }

    private static async Task AssertGeneratedOutputsAsync(
        DefaultHttpContext context,
        CaptureProvider capture,
        string? rejectedRawValue)
    {
        var correlationId = context.GetCorrelationId();
        Assert.Matches(GeneratedIdPattern(), correlationId);

        var scope = Assert.Single(capture.OpenedScopes);
        Assert.Equal(correlationId, ScopeField(scope, "CorrelationId"));

        await StartResponseAsync(context);
        Assert.Equal(correlationId, context.Response.Headers[HeaderName]);

        if (!string.IsNullOrEmpty(rejectedRawValue))
        {
            // The rejected raw value appears in none of this feature's outputs. Values whose
            // rejection outputs would embed it (for example line-break encodings) are absent too.
            Assert.DoesNotContain(
                rejectedRawValue,
                context.Response.Headers[HeaderName].ToString(),
                StringComparison.Ordinal);
        }
    }

    // ---- Downstream rewrite: the slot stays authoritative ----

    [Fact]
    public async Task DownstreamHeaderRewrite_DoesNotChangeSlotOrResponseValue()
    {
        const string original = "original-value";
        string? accessorDuringRewrite = null;

        var context = await InvokeAsync(
            async httpContext =>
            {
                httpContext.Request.Headers[HeaderName] = "tampered-request";
                httpContext.Response.Headers[HeaderName] = "tampered-response";
                accessorDuringRewrite = httpContext.GetCorrelationId();
                await Task.CompletedTask;
            },
            prepareRequest: request => request.Headers[HeaderName] = original);

        Assert.Equal(original, accessorDuringRewrite);
        Assert.Equal(original, context.GetCorrelationId());
        await StartResponseAsync(context);
        // The library writes the resolved single value back when the response starts; it does not
        // re-parse the request header, and the downstream response-header write is replaced.
        var values = Assert.Single(context.Response.Headers, header => header.Key == HeaderName);
        Assert.Equal(original, values.Value.ToString());
    }

    // ---- Exceptions and cancellation flow through untouched ----

    [Fact]
    public async Task DownstreamException_PropagatesAndReleasesScopeWithoutLogging()
    {
        var capture = new CaptureProvider();
        var expected = new InvalidOperationException("downstream failure");

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            InvokeAsync(_ => throw expected, capture));

        Assert.Same(expected, thrown);
        // The scope was opened for the request and released when it ended.
        Assert.Single(capture.OpenedScopes);
        Assert.Equal(0, capture.ActiveScopeCount);
        // The middleware itself logs nothing; the removed local middleware's duplicate LogError is
        // not reintroduced.
        Assert.Empty(capture.LogEntries);
    }

    [Fact]
    public async Task DownstreamCancellation_PropagatesAndIsNotSwallowed()
    {
        var capture = new CaptureProvider();
        using var cancellation = new CancellationTokenSource();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            InvokeAsync(
                context => throw new OperationCanceledException(context.RequestAborted),
                capture));

        Assert.Equal(0, capture.ActiveScopeCount);
        Assert.Empty(capture.LogEntries);
    }

    // ---- Concurrency: interleaved requests keep isolated slots and scopes ----

    [Fact]
    public async Task InterleavedConcurrentRequests_KeepIsolatedSlotsScopesAndResponses()
    {
        const int pairs = 16;
        var capture = new CaptureProvider();

        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(capture));
        services.AddSignaCoreServiceMantle();
        var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider);
        app.UseServiceMantleCorrelationId();

        var arrivals = new TaskCompletionSource[2 * pairs];
        var contexts = new DefaultHttpContext[2 * pairs];
        var expected = new string[2 * pairs];
        for (var i = 0; i < arrivals.Length; i++)
        {
            arrivals[i] = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        app.Run(async httpContext =>
        {
            var index = (int)(httpContext.Items["test-index"] ?? -1);
            arrivals[index].SetResult();
            // Both members of the pair are now inside their scopes at the same time.
            await arrivals[index ^ 1].Task;
        });
        var pipeline = app.Build();

        var requests = new Task[2 * pairs];
        for (var i = 0; i < 2 * pairs; i++)
        {
            expected[i] = $"pair-{i / 2:00}-{(i % 2 == 0 ? 'a' : 'b')}";
            var index = i;
            contexts[i] = new DefaultHttpContext();
            contexts[i].Features.Set<IHttpResponseFeature>(
                new ResponseStartFeature(contexts[i].Features.Get<IHttpResponseFeature>()!));
            contexts[i].Items["test-index"] = index;
            contexts[i].Request.Headers[HeaderName] = expected[i];
            requests[i] = pipeline(contexts[i]);
        }

        await Task.WhenAll(requests);

        for (var i = 0; i < 2 * pairs; i++)
        {
            Assert.Equal(expected[i], contexts[i].GetCorrelationId());
            await StartResponseAsync(contexts[i]);
            Assert.Equal(expected[i], contexts[i].Response.Headers[HeaderName].ToString());
        }

        // Every request opened exactly its own scope; 2*pairs distinct correlation fields were seen.
        Assert.Equal(2 * pairs, capture.OpenedScopes.Count);
        Assert.Equal(2 * pairs, capture.OpenedScopes.Select(scope => ScopeField(scope, "CorrelationId")).Distinct().Count());
    }
}
