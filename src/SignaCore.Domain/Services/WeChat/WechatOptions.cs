namespace SignaCore.Domain.Services.WeChat;

public class WechatOptions
{
    public string AppId { get; set; } = string.Empty;
    public string AppSecret { get; set; } = string.Empty;
    public string ApiBaseUrl { get; set; } = "https://api.weixin.qq.com";
}
