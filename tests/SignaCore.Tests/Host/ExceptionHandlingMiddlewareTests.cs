using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class ExceptionHandlingMiddlewareTests
{
    private static ExceptionHandlingMiddleware CreateMiddleware(RequestDelegate next)
    {
        return new ExceptionHandlingMiddleware(next, NullLogger<ExceptionHandlingMiddleware>.Instance);
    }

    private static async Task<(int StatusCode, string Body)> InvokeAsync(RequestDelegate next)
    {
        var middleware = CreateMiddleware(next);
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var body = await new StreamReader(context.Response.Body).ReadToEndAsync();
        return (context.Response.StatusCode, body);
    }

    [Fact]
    public async Task InvokeAsync_NoException_PassesThrough()
    {
        var (status, _) = await InvokeAsync(context =>
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        });

        Assert.Equal(StatusCodes.Status200OK, status);
    }

    [Fact]
    public async Task InvokeAsync_ArgumentException_Returns400()
    {
        var (status, body) = await InvokeAsync(_ => throw new ArgumentException("secret field detail"));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(400, doc.RootElement.GetProperty("Status").GetInt32());
        Assert.Equal("Bad Request", doc.RootElement.GetProperty("Title").GetString());
    }

    [Fact]
    public async Task InvokeAsync_InvalidOperationException_Returns409()
    {
        var (status, body) = await InvokeAsync(_ => throw new InvalidOperationException("internal state detail"));

        Assert.Equal(StatusCodes.Status409Conflict, status);
        using var doc = JsonDocument.Parse(body);
        Assert.Equal("Conflict", doc.RootElement.GetProperty("Title").GetString());
    }

    [Fact]
    public async Task InvokeAsync_UnhandledException_Returns500()
    {
        var (status, body) = await InvokeAsync(_ => throw new Exception("database connection string xyz"));

        Assert.Equal(StatusCodes.Status500InternalServerError, status);
        using var doc = JsonDocument.Parse(body);
        Assert.Equal("Internal Server Error", doc.RootElement.GetProperty("Title").GetString());
        Assert.Equal("An internal error occurred.", doc.RootElement.GetProperty("Detail").GetString());
    }

    [Theory]
    [InlineData("secret field detail")]
    [InlineData("database connection string xyz")]
    public async Task InvokeAsync_ResponseBody_NeverLeaksExceptionMessage(string exceptionMessage)
    {
        var (_, body) = await InvokeAsync(_ => throw new Exception(exceptionMessage));

        Assert.DoesNotContain(exceptionMessage, body);
    }
    public static TheoryData<string, bool, bool> ExceptionCases => new(
        from kind in new[] { "argument", "invalid-operation", "other", "cancel", "task-cancel" }
        from aborted in new[] { false, true }
        from started in new[] { false, true }
        select (kind, aborted, started));

    [Theory]
    [MemberData(nameof(ExceptionCases))]
    public async Task InvokeAsync_ClassifiesCancellationAndPreservesStartedResponse(
        string kind, bool aborted, bool started)
    {
        const string privateMarker = "private-exception-marker";
        using var cancellation = new CancellationTokenSource();
        if (aborted) cancellation.Cancel();
        Exception failure = kind switch
        {
            "argument" => new ArgumentException(privateMarker),
            "invalid-operation" => new InvalidOperationException(privateMarker),
            // A different cancellation source must still be classified by RequestAborted.
            "cancel" => new OperationCanceledException(privateMarker),
            "task-cancel" => new TaskCanceledException(privateMarker),
            _ => new Exception(privateMarker)
        };
        var context = new DefaultHttpContext { RequestAborted = cancellation.Token };
        using var body = new MemoryStream();
        if (started)
            context.Features.Set<IHttpResponseFeature>(new StartedResponseFeature(body));
        else
        {
            context.Response.Body = body;
            context.Response.StatusCode = StatusCodes.Status202Accepted;
        }
        var logger = new RecordingLogger();
        var middleware = new ExceptionHandlingMiddleware(_ => throw failure, logger);

        await middleware.InvokeAsync(context);

        var clientCancellation = aborted && failure is OperationCanceledException;
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(clientCancellation ? LogLevel.Debug : LogLevel.Error, entry.Level);
        Assert.Null(entry.Exception);
        Assert.DoesNotContain(privateMarker, entry.Message);
        if (started || clientCancellation)
        {
            Assert.Equal(StatusCodes.Status202Accepted, context.Response.StatusCode);
            Assert.Equal(0, body.Length);
            Assert.Null(context.Response.ContentType);
        }
        else
        {
            var status = kind switch { "argument" => 400, "invalid-operation" => 409, _ => 500 };
            Assert.Equal(status, context.Response.StatusCode);
            Assert.Equal("application/json", context.Response.ContentType);
            var content = System.Text.Encoding.UTF8.GetString(body.ToArray());
            Assert.DoesNotContain(privateMarker, content);
            using var json = JsonDocument.Parse(content);
            Assert.Equal(3, json.RootElement.EnumerateObject().Count());
            Assert.Equal(status, json.RootElement.GetProperty("Status").GetInt32());
            Assert.Equal(status switch { 400 => "Bad Request", 409 => "Conflict", _ => "Internal Server Error" },
                json.RootElement.GetProperty("Title").GetString());
            Assert.Equal(status == 500 ? "An internal error occurred." :
                "The request could not be processed. See server logs for details.",
                json.RootElement.GetProperty("Detail").GetString());
        }
    }

    private sealed class StartedResponseFeature(Stream body) : IHttpResponseFeature
    {
        public int StatusCode
        {
            get => StatusCodes.Status202Accepted;
            set => throw new InvalidOperationException("The response has already started.");
        }
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary { IsReadOnly = true };
        public Stream Body { get; set; } = body;
        public bool HasStarted => true;
        public void OnStarting(Func<object, Task> callback, object state) { }
        public void OnCompleted(Func<object, Task> callback, object state) { }
    }

    private sealed class RecordingLogger : ILogger<ExceptionHandlingMiddleware>
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, formatter(state, exception), exception));
    }

}
