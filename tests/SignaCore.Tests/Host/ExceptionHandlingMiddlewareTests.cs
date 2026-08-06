using System.Text.Json;
using Microsoft.AspNetCore.Http;
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
}
