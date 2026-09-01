namespace SignaCore.Host.Models;

// The end-user self-service API (/api/profile/*, JwtBearer plus the UserProfile policy).

public sealed record ProfileResponse(
    string UserId,
    string? Nickname,
    bool IsActive,
    long CreatedAt);

public sealed record UpdateProfileNicknameRequest(string? Nickname);

public sealed record BindWechatRequest(string? Code);

/// <summary>WeChat binding status. <paramref name="OpenId"/> is masked; the raw value never leaves the service.</summary>
public sealed record WechatBindingResponse(bool Bound, string? OpenId);
