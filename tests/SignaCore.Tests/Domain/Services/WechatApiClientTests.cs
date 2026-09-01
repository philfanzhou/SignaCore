using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Domain.Services.WeChat;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class WechatApiClientTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(_responder(request));
        }
    }

    private static WechatApiClient CreateClient(FakeHandler handler)
    {
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.weixin.qq.com") };
        var options = new WechatOptions { AppId = "wx-app-id", AppSecret = "wx-secret" };
        return new WechatApiClient(httpClient, options, NullLogger<WechatApiClient>.Instance);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    [Fact]
    public async Task CodeToSessionAsync_Success_ReturnsOpenId()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"openid":"o-abc","session_key":"sk"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Equal("o-abc", result);
        var query = handler.LastRequest!.RequestUri!.Query;
        Assert.Contains("appid=wx-app-id", query);
        Assert.Contains("secret=wx-secret", query);
        Assert.Contains("js_code=code-1", query);
        Assert.Contains("grant_type=authorization_code", query);
    }

    /// <summary>
    /// A jscode2session failure comes back as HTTP 200 with a <b>numeric</b> errcode. ErrCode used to
    /// be declared as a string, which made a real response throw JsonException during
    /// deserialization and be swallowed — this test pins the numeric shape.
    /// </summary>
    [Fact]
    public async Task CodeToSessionAsync_NumericErrorCode_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"errcode":40029,"errmsg":"invalid code"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("bad-code", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_QuotedErrorCode_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"errcode":"40029","errmsg":"invalid code"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("bad-code", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    /// <summary>An errcode of 0 means success and must not be treated as a failure.</summary>
    [Fact]
    public async Task CodeToSessionAsync_ZeroErrorCode_ReturnsOpenId()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"errcode":0,"openid":"o-abc","session_key":"sk"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Equal("o-abc", result);
    }

    [Fact]
    public async Task CodeToSessionAsync_SessionWithoutOpenId_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"session_key":"sk"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_WithoutCredentials_DoesNotCallWechat()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"openid":"o-abc"}"""));
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.weixin.qq.com") };
        var client = new WechatApiClient(httpClient, new WechatOptions(), NullLogger<WechatApiClient>.Instance);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Null(handler.LastRequest);
    }

    /// <summary>
    /// Regression: the Content-Type of jscode2session is text/plain. ReadFromJsonAsync used to throw
    /// NotSupportedException, which is not a JsonException, so it escaped the catch and became an
    /// unhandled exception reported as HTTP 500. Every older test used the application/json helper
    /// and happened to sidestep the real shape.
    /// </summary>
    [Fact]
    public async Task CodeToSessionAsync_WithWechatsTextPlainContentType_ReturnsOpenId()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"openid":"o-abc","session_key":"sk"}""", Encoding.UTF8, "text/plain")
        });
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Equal("o-abc", result);
    }

    [Fact]
    public async Task CodeToSessionAsync_WithTextPlainErrorPayload_ReturnsNull()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"errcode":40029,"errmsg":"invalid code"}""", Encoding.UTF8, "text/plain")
        });
        var client = CreateClient(handler);

        Assert.Null(await client.CodeToSessionAsync("bad-code", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A non-JSON body, such as a gateway error page, also has to count as a failed sign-in rather
    /// than propagate as an exception.
    /// </summary>
    [Fact]
    public async Task CodeToSessionAsync_WithNonJsonBody_ReturnsNull()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<html>gateway error</html>", Encoding.UTF8, "text/html")
        });
        var client = CreateClient(handler);

        Assert.Null(await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CodeToSessionAsync_HttpError_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.InternalServerError, "{}"));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_RequestThrows_ReturnsNull()
    {
        var handler = new FakeHandler(_ => throw new HttpRequestException("network down"));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_NullBody_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, "null"));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }
}
