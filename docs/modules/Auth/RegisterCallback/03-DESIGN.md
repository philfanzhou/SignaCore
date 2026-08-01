# 回调注册 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Host/Controllers/AuthController.cs         # POST /api/auth/callback/register HTTP 端点
├── Host/Models/AuthModels.cs                 # RegisterCallbackRequest / RegisterCallbackResponse DTO
├── Domain/Services/CallbackUrlValidator.cs   # 回调 URL 格式验证
└── Database/
    ├── Entity/AppRegistrationEntity.cs        # 应用注册实体
    └── Repositories/IAppRegistrationRepository.cs
```

## 关键接口签名

```csharp
// HTTP 端点（AuthController）
[HttpPost("callback/register")]
public async Task<ActionResult<RegisterCallbackResponse>> RegisterCallback(
    [FromBody] RegisterCallbackRequest request)

// 请求/响应 DTO（见 AuthModels.cs）
public sealed class RegisterCallbackRequest { string CallbackUrl; int TtlSeconds; }
public sealed class RegisterCallbackResponse { bool Success; string Message; long ExpiresAt; }
```

## 依赖的数据库表

- [app_registrations](../../../database/tables/app_registrations.md) — 更新 CallbackUrl 和 CallbackExpiresAt

## 数据流

```
RegisterCallback Request
    │
    ▼
Validate AppId/AppSecret not empty
    │
    ▼
CallbackUrlValidator.Validate(CallbackUrl)（如果 CallbackUrl 非空）
    │   └── 检查 URL 格式（必须是有效的 HTTP/HTTPS 绝对 URL）
    │   └── 检查是否解析到私有 IP 地址（仅当显式配置 AllowPrivateAddresses=false 时拒绝）
    │   └── 检查域名是否在白名单中（如果配置了 AllowedDomains）
    │
    ▼
AppRegistrationRepository.GetByAppIdAsync
    │
    ▼
BCrypt.Verify(AppSecret, AppSecretHash)
    │
    ▼
Update CallbackUrl + CallbackExpiresAt
    │
    ▼
SaveChangesAsync
    │
    ▼
RegisterCallbackResponse
```
