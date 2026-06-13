using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Domain.Services.WeChat;

public interface IWechatApiClient
{
    Task<string?> CodeToSessionAsync(string code);
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

    public async Task<string?> CodeToSessionAsync(string code)
    {
        try
        {
            var url = $"/sns/jscode2session?appid={_options.AppId}&secret={_options.AppSecret}&js_code={code}&grant_type=authorization_code";
            var response = await _httpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<WechatSessionResponse>();
            if (result == null)
            {
                _logger.LogWarning("WeChat API returned null response");
                return null;
            }

            if (!string.IsNullOrEmpty(result.ErrCode) && result.ErrCode != "0")
            {
                _logger.LogWarning("WeChat API error: ErrCode={ErrCode}, ErrMsg={ErrMsg}", result.ErrCode, result.ErrMsg);
                return null;
            }

            return result.OpenId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WeChat API request failed");
            return null;
        }
    }

    private class WechatSessionResponse
    {
        public string OpenId { get; set; } = string.Empty;
        public string SessionKey { get; set; } = string.Empty;
        public string? UnionId { get; set; }
        public string? ErrCode { get; set; }
        public string? ErrMsg { get; set; }
    }
}
