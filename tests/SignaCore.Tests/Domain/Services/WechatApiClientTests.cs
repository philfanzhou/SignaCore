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

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Equal("o-abc", result);
        var query = handler.LastRequest!.RequestUri!.Query;
        Assert.Contains("appid=wx-app-id", query);
        Assert.Contains("secret=wx-secret", query);
        Assert.Contains("js_code=code-1", query);
        Assert.Contains("grant_type=authorization_code", query);
    }

    /// <summary>
    /// jscode2session 的失败响应是 HTTP 200 + **数字** errcode。之前 ErrCode 声明成 string，
    /// 真实响应会在反序列化时抛 JsonException 被吞掉——这条用例锁定数字形态。
    /// </summary>
    [Fact]
    public async Task CodeToSessionAsync_NumericErrorCode_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"errcode":40029,"errmsg":"invalid code"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("bad-code");

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_QuotedErrorCode_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"errcode":"40029","errmsg":"invalid code"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("bad-code");

        Assert.Null(result);
    }

    /// <summary>errcode 为 0 是成功语义，不能当失败处理。</summary>
    [Fact]
    public async Task CodeToSessionAsync_ZeroErrorCode_ReturnsOpenId()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"errcode":0,"openid":"o-abc","session_key":"sk"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Equal("o-abc", result);
    }

    [Fact]
    public async Task CodeToSessionAsync_SessionWithoutOpenId_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"session_key":"sk"}"""));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_WithoutCredentials_DoesNotCallWechat()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"openid":"o-abc"}"""));
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.weixin.qq.com") };
        var client = new WechatApiClient(httpClient, new WechatOptions(), NullLogger<WechatApiClient>.Instance);

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Null(result);
        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task CodeToSessionAsync_HttpError_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.InternalServerError, "{}"));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_RequestThrows_ReturnsNull()
    {
        var handler = new FakeHandler(_ => throw new HttpRequestException("network down"));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Null(result);
    }

    [Fact]
    public async Task CodeToSessionAsync_NullBody_ReturnsNull()
    {
        var handler = new FakeHandler(_ => Json(HttpStatusCode.OK, "null"));
        var client = CreateClient(handler);

        var result = await client.CodeToSessionAsync("code-1");

        Assert.Null(result);
    }
}
