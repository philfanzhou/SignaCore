using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed partial class BoundedOidcFormGateTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task Logout_CancellationAfterEachReadIncludingEof_KeepsOriginalTokenAndClearsData(int read)
    {
        using var caller = new CancellationTokenSource();
        var calls = 0;
        var stream = new ChunkedMemoryStream(Encoding.ASCII.GetBytes("a=123456"), 2)
        {
            AfterRead = () => { if (++calls == read) caller.Cancel(); }
        };
        var (context, next, invoked) = CreateContext("/oauth2/logout/requests", stream);
        context.RequestAborted = caller.Token;
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context));
        Assert.Equal(caller.Token, error.CancellationToken);
        Assert.Equal(caller.Token, stream.ObservedToken);
        Assert.Equal(read, calls);
        Assert.False(stream.Retained.IsEmpty);
        Assert.All(stream.Retained.ToArray(), value => Assert.Equal(0, value));
        Assert.False(invoked.Value);
        Assert.Null(context.Features.Get<IFormFeature>());
        Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
    }

    [Theory]
    [InlineData("a=%252B", "%2B")]
    [InlineData("a=+", " ")]
    [InlineData("a=%2B", "+")]
    [InlineData("a=%C3%B6", "ö")]
    public async Task Logout_StrictSingleDecode_IsCached(string body, string expected)
    {
        var stream = new ChunkedMemoryStream(Encoding.ASCII.GetBytes(body), 1);
        var (context, next, _) = CreateContext("/oauth2/logout/requests", stream);
        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);
        Assert.Equal(expected, context.Request.Form["a"].ToString());
        Assert.Same(context.Request.Form, await context.Request.ReadFormAsync(TestContext.Current.CancellationToken));
        Assert.Equal(body.Length, stream.TotalRead);
    }

    [Fact]
    public async Task Logout_GetNeverReadsBody()
    {
        foreach (var path in new[] { "/oauth2/logout", "/oauth2/logout/requests" })
        {
            var stream = new ChunkedMemoryStream(Encoding.ASCII.GetBytes("a=b"), 1);
            var (context, next, invoked) = CreateContext(path, stream);
            context.Request.Method = "GET";
            await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);
            Assert.Equal(0, stream.TotalRead);
            Assert.True(invoked.Value);
            Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
        }
    }
}
