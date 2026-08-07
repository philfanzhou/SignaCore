using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace SignaCore.Domain.Services.WeChat;

public interface IWechatApiClient
{
    Task<string?> CodeToSessionAsync(string code, CancellationToken cancellationToken = default);
}

public class WechatApiClient : IWechatApiClient
{
    private readonly HttpClient _httpClient;
    private readonly WechatOptions _options;
    private readonly ILogger<WechatApiClient> _logger;

    public WechatApiClient(HttpClient httpClient, WechatOptions options, ILogger<WechatApiClient> logger)
    {
        _httpClient = httpClient;
        _options = options;
        _logger = logger;
    }

    public async Task<string?> CodeToSessionAsync(string code, CancellationToken cancellationToken = default)
    {
        if (!_options.IsConfigured)
        {
            _logger.LogError("WeChat login was attempted while WeChat:AppId/AppSecret are not configured");
            return null;
        }

        try
        {
            var url = $"/sns/jscode2session?appid={Uri.EscapeDataString(_options.AppId)}&secret={Uri.EscapeDataString(_options.AppSecret)}&js_code={Uri.EscapeDataString(code)}&grant_type=authorization_code";
            var response = await _httpClient.GetAsync(url, cancellationToken);
            response.EnsureSuccessStatusCode();

            // jscode2session 的 Content-Type 是 text/plain，不是 application/json。
            // ReadFromJsonAsync 会先校验媒体类型并抛 NotSupportedException，所以这里显式
            // 读字符串再反序列化，不依赖对端把 Content-Type 写对。
            var payload = await response.Content.ReadAsStringAsync(cancellationToken);
            var result = JsonSerializer.Deserialize<WechatSessionResponse>(payload, SerializerOptions);
            if (result == null)
            {
                _logger.LogWarning("WeChat API returned null response");
                return null;
            }

            // jscode2session reports failures as a JSON *number* errcode with HTTP 200.
            if (result.ErrCode is not (null or 0))
            {
                _logger.LogWarning("WeChat API error: ErrCode={ErrCode}, ErrMsg={ErrMsg}", result.ErrCode, result.ErrMsg);
                return null;
            }

            if (string.IsNullOrEmpty(result.OpenId))
            {
                _logger.LogWarning("WeChat API returned a session without an OpenId");
                return null;
            }

            return result.OpenId;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or OperationCanceledException)
        {
            // 登录失败要能被上层当成"认证失败"处理，不能变成未处理异常打成 500。
            _logger.LogError(ex, "WeChat API request failed");
            return null;
        }
    }

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Property names are pinned explicitly: WeChat returns <c>openid</c> / <c>errcode</c> /
    /// <c>errmsg</c> / <c>session_key</c>, and case-insensitive matching alone does not bridge
    /// the underscore in <c>session_key</c>. <see cref="ErrCode"/> is numeric in real responses;
    /// <see cref="JsonNumberHandling.AllowReadingFromString"/> also accepts the quoted form some
    /// gateways emit.
    /// </summary>
    private sealed class WechatSessionResponse
    {
        [JsonPropertyName("openid")]
        public string? OpenId { get; set; }

        [JsonPropertyName("session_key")]
        public string? SessionKey { get; set; }

        [JsonPropertyName("unionid")]
        public string? UnionId { get; set; }

        [JsonPropertyName("errcode")]
        [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
        public int? ErrCode { get; set; }

        [JsonPropertyName("errmsg")]
        public string? ErrMsg { get; set; }
    }
}
