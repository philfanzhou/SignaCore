using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;
using SignaCore.Host;
using SignaCore.Tests.Integration;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// The two rejection responses the host writes itself. Both must observe the request's cancellation
/// token while writing, and neither may change its status code, content type or body text.
/// <para>
/// Uses a dedicated server fixture because these tests intentionally exhaust limiter partitions.
/// </para>
/// </summary>
public sealed class HostRejectionWriteCancellationTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public HostRejectionWriteCancellationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task GlobalRateLimitRejection_WritesTheUnchangedBody()
    {
        var onRejected = ResolveOnRejected();
        var context = new DefaultHttpContext();
        using var body = new MemoryStream();
        context.Response.Body = body;

        await onRejected(
            new OnRejectedContext { HttpContext = context, Lease = new RejectedLease() },
            TestContext.Current.CancellationToken);

        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
        Assert.Equal("application/json", context.Response.ContentType);
        Assert.Equal(
            """{"status":429,"title":"Too Many Requests","detail":"Rate limit exceeded. Please try again later."}""",
            System.Text.Encoding.UTF8.GetString(body.ToArray()));
    }

    /// <summary>
    /// The rejection callback receives a cancellation token as its second argument; the write has to
    /// observe it rather than the default one, so a client that is gone stops the write.
    /// </summary>
    [Fact]
    public async Task GlobalRateLimitRejection_WritesWithTheCallbackToken()
    {
        var onRejected = ResolveOnRejected();
        using var cancellation = new CancellationTokenSource();
        var context = new DefaultHttpContext();
        using var body = new CancelProbeStream(cancellation);
        context.Response.Body = body;

        try
        {
            await onRejected(new OnRejectedContext { HttpContext = context, Lease = new RejectedLease() }, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            // Cancelling from inside the write is exactly what an aborted client does.
        }

        Assert.True(body.WriteObservedTheProbedToken);
        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
    }

    /// <summary>
    /// The JWKS limiter answers over its own quota with a plain-text 429. The write runs on
    /// <c>context.RequestAborted</c>, which this test replaces with a token it can cancel from
    /// inside the write.
    /// </summary>
    [Fact]
    public async Task JwksRateLimitRejection_WritesTheUnchangedBodyWithTheRequestToken()
    {
        var probe = new ResponseWriteProbe();
        using var factory = _fixture.WithTestServices(services =>
            services.AddSingleton<IStartupFilter>(new ResponseWriteProbeStartupFilter(probe)));
        using var http = factory.CreateClient();

        HttpStatusCode? rejected = null;
        string? rejectedBody = null;
        for (var attempt = 0; attempt < 61 && rejected == null; attempt++)
        {
            using var response = await http.GetAsync(
                WellKnownEndpoints.Jwks, TestContext.Current.CancellationToken);
            if (response.StatusCode != HttpStatusCode.TooManyRequests) continue;
            rejected = response.StatusCode;
            rejectedBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, rejected);
        Assert.Equal("Too many requests to JWKS endpoint. Please try again later.", rejectedBody);
        Assert.True(probe.WriteObservedTheRequestToken);
    }

    private Func<OnRejectedContext, CancellationToken, ValueTask> ResolveOnRejected()
    {
        var options = _fixture.Services.GetRequiredService<IOptions<RateLimiterOptions>>().Value;
        return Assert.IsType<Func<OnRejectedContext, CancellationToken, ValueTask>>(options.OnRejected);
    }

    /// <summary>
    /// Cancels the source the caller passed to the write, then reports whether the token the stream
    /// received observed that cancellation — true only when the write is running on the caller's
    /// token rather than on the default one.
    /// </summary>
    private sealed class CancelProbeStream(CancellationTokenSource cancellation) : MemoryStream
    {
        public bool WriteObservedTheProbedToken { get; private set; }

        public override Task WriteAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Probe(cancellationToken);
            return base.WriteAsync(buffer, offset, count, CancellationToken.None);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Probe(cancellationToken);
            return base.WriteAsync(buffer, CancellationToken.None);
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            Probe(cancellationToken);
            return base.FlushAsync(CancellationToken.None);
        }

        private void Probe(CancellationToken cancellationToken)
        {
            if (WriteObservedTheProbedToken) return;
            cancellation.Cancel();
            WriteObservedTheProbedToken = cancellationToken.IsCancellationRequested;
        }
    }

    /// <summary>The rejected lease the middleware would hand the callback.</summary>
    private sealed class RejectedLease : RateLimitLease
    {
        public override bool IsAcquired => false;

        public override IEnumerable<string> MetadataNames => [];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            metadata = null;
            return false;
        }
    }

    private sealed class ResponseWriteProbe
    {
        public bool WriteObservedTheRequestToken { get; set; }
    }

    /// <summary>
    /// Runs before the host's own middleware so the JWKS branch writes into a stream this test
    /// controls, on a request token this test can cancel.
    /// </summary>
    private sealed class ResponseWriteProbeStartupFilter(ResponseWriteProbe probe) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, continuation) =>
            {
                if (!WellKnownEndpoints.IsJwks(context.Request.Path.Value ?? string.Empty))
                {
                    await continuation(context);
                    return;
                }

                using var cancellation = new CancellationTokenSource();
                context.RequestAborted = cancellation.Token;
                var original = context.Response.Body;
                await using var body = new ProbedResponseStream(context, original, cancellation, probe);
                context.Response.Body = body;
                try
                {
                    await continuation(context);
                }
                catch (OperationCanceledException)
                {
                    // Cancelling from inside the rejection write is exactly what an aborted client
                    // does; the assertion is on what the write observed.
                }
                finally
                {
                    context.Response.Body = original;
                }
            });
            next(app);
        };
    }

    /// <summary>
    /// Writes through to the real response body, but only after cancelling the request token and
    /// recording whether the write's own token observed it.
    /// </summary>
    private sealed class ProbedResponseStream(
        HttpContext context,
        Stream inner,
        CancellationTokenSource cancellation,
        ResponseWriteProbe probe) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            Probe(cancellationToken);
            return inner.FlushAsync(CancellationToken.None);
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);

        public override void SetLength(long value) => inner.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) =>
            inner.Write(buffer, offset, count);

        public override Task WriteAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Probe(cancellationToken);
            return inner.WriteAsync(buffer, offset, count, CancellationToken.None);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Probe(cancellationToken);
            return inner.WriteAsync(buffer, CancellationToken.None);
        }

        // Only the rejection write is under test: a served key set must not be disturbed.
        private void Probe(CancellationToken cancellationToken)
        {
            if (probe.WriteObservedTheRequestToken ||
                context.Response.StatusCode != StatusCodes.Status429TooManyRequests)
            {
                return;
            }

            cancellation.Cancel();
            probe.WriteObservedTheRequestToken = cancellationToken.IsCancellationRequested;
        }
    }
}
