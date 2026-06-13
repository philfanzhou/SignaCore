# 统一 Token 获取 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Contract/Protos/auth.proto          # gRPC 接口定义
├── Service/AuthServiceImpl.cs          # gRPC 服务实现（GetToken 入口）
├── Domain/
│   ├── Validators/
│   │   ├── IIdentityValidator.cs       # 验证器接口
│   │   ├── ValidatorFactory.cs         # 验证器工厂
│   │   ├── PasswordValidator.cs        # 密码登录验证
│   │   ├── SmsValidator.cs             # 短信登录验证
│   │   ├── WechatValidator.cs          # 微信登录验证
│   │   └── RefreshTokenValidator.cs    # 刷新令牌验证
│   ├── ClaimsResolver.cs               # Claims 构建
│   ├── CallbackService.cs              # 回调权限注入
│   ├── Services/
│   │   ├── TokenService.cs             # JWT 签发
│   │   ├── GatewayValidationService.cs # 网关验证
│   │   ├── CallbackUrlValidator.cs     # 回调 URL 验证
│   │   ├── Sms/DbOtpService.cs         # OTP 验证
│   │   └── WeChat/WechatApiClient.cs   # 微信 API 客户端
│   ├── KeyManager.cs                   # RSA 密钥管理
│   └── AuthMetrics.cs                  # 指标收集
└── Database/
    ├── Entity/AccountEntity.cs          # 账户实体
    ├── Entity/PasswordCredentialEntity.cs
    ├── Entity/UserLoginEntity.cs
    ├── Entity/RefreshTokenEntity.cs
    ├── Entity/AppRegistrationEntity.cs
    ├── Entity/LoginAttemptEntity.cs
    └── Repositories/IRepositories.cs    # 仓储接口
```

## 关键接口签名和数据结构定义

```csharp
// gRPC 接口
service AuthGrpcService {
  rpc GetToken(GetTokenRequest) returns (TokenResponse);
}

// 验证器接口
public interface IIdentityValidator {
    string GrantType { get; }
    Task<ValidationResult> ValidateAsync(ValidationRequest request);
}

// 验证结果
public class ValidationResult {
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public AccountEntity? Account { get; set; }
    public string? AuthMethod { get; set; }
    public string? DisplayName { get; set; }
}

// 回调服务接口
public interface ICallbackService {
    Task<List<Claim>> FetchExternalClaimsAsync(string callbackUrl, string userId);
}
```

## 依赖的数据库表/字段/索引

- [accounts](../../database/tables/accounts.md) — 账户查询和登录信息更新
- [password_credentials](../../database/tables/password_credentials.md) — 密码凭证验证
- [user_logins](../../database/tables/user_logins.md) — 外部登录绑定查询
- [refresh_tokens](../../database/tables/refresh_tokens.md) — 刷新令牌生成和验证
- [app_registrations](../../database/tables/app_registrations.md) — 网关验证和回调配置
- [login_attempts](../../database/tables/login_attempts.md) — 登录失败计数和锁定
- [login_histories](../../database/tables/login_histories.md) — 登录审计记录

## 数据流/调用链

```
GetToken Request
    │
    ▼
ValidateGatewayAsync ──▶ GatewayValidationService.ValidateAsync
    │                         │
    │                         └──▶ AppRegistrationRepository.GetByAppIdAsync
    │                         └──▶ BCrypt.Verify(AppSecret)
    │
    ▼
ValidatorFactory.GetValidator(grantType)
    │
    ▼
IIdentityValidator.ValidateAsync
    │  ├── PasswordValidator ──▶ PasswordCredentialRepo + AccountRepo + LoginAttemptRepo
    │  ├── SmsValidator ──▶ OtpService.VerifyAsync + AccountRepo + UserLoginRepo
    │  ├── WechatValidator ──▶ WechatApiClient.CodeToSessionAsync + AccountRepo
    │  └── RefreshTokenValidator ──▶ RefreshTokenRepo + AccountRepo
    │
    ▼
ClaimsResolver.ResolveBasicClaims
    │
    ▼
CallbackService.FetchExternalClaimsAsync (if CallbackUrl exists)
    │
    ▼
JwtTokenService.GenerateJwtToken (RSA signing)
    │
    ▼
HandleRefreshTokenAsync (generate/revoke)
    │
    ▼
AuditService.RecordLoginAsync
    │
    ▼
UpdateAccountLoginInfoAsync
    │
    ▼
TokenResponse
```

## 关键设计决策和取舍理由

1. **策略模式验证器**：通过 `IIdentityValidator` + `ValidatorFactory` 实现开闭原则，新增登录方式只需实现接口并注册 DI
2. **回调降级不阻塞**：回调失败返回空 Claims，确保登录流程不中断 [推断]
3. **刷新令牌一次性使用**：使用后立即撤销并生成新令牌，降低令牌泄露风险
4. **短信登录自动注册**：降低注册门槛，首次短信登录自动创建账户
5. **微信登录不自动注册**：微信 OpenId 需预先绑定到已有账户，防止未授权访问
