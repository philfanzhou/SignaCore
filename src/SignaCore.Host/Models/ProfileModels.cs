namespace SignaCore.Host.Models;

// 终端用户自助接口（/api/profile/*，JwtBearer + UserProfile 策略）。

public sealed record ProfileResponse(
    string UserId,
    string? Nickname,
    bool IsActive,
    long CreatedAt);

public sealed record UpdateProfileNicknameRequest(string? Nickname);
