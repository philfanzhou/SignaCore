namespace SignaCore.Domain.Services.WeChat;

public class WechatOptions
{
    public const string SectionName = "WeChat";

    public string AppId { get; set; } = string.Empty;
    public string AppSecret { get; set; } = string.Empty;
    public string ApiBaseUrl { get; set; } = "https://api.weixin.qq.com";

    /// <summary>
    /// Whether credentials are present. Applications may still carry
    /// <see cref="Database.Entity.WechatLoginMode.Disabled"/>, so this is not a startup requirement:
    /// it is what turns an unconfigured deployment into an explicit login failure instead of a
    /// request to WeChat with an empty appid.
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(AppId) && !string.IsNullOrWhiteSpace(AppSecret);

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(AppId) != string.IsNullOrWhiteSpace(AppSecret))
        {
            throw new InvalidOperationException(
                "WeChat:AppId and WeChat:AppSecret must both be configured, or both be omitted.");
        }

        // https everywhere except loopback, which is how a local stub replaces api.weixin.qq.com.
        if (!Uri.TryCreate(ApiBaseUrl, UriKind.Absolute, out var baseUri) ||
            (baseUri.Scheme != Uri.UriSchemeHttps && !baseUri.IsLoopback))
        {
            throw new InvalidOperationException(
                "WeChat:ApiBaseUrl must be an absolute https URL (http is accepted only for loopback stubs).");
        }
    }
}
