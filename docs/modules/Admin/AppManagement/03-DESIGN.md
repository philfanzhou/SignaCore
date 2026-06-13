# 应用注册管理 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Host/Controllers/AdminController.cs     # App 管理 API
├── Host/Models/AdminModels.cs              # 请求/响应模型
├── Domain/Services/AuditService.cs         # 审计日志
└── Database/
    ├── Entity/AppRegistrationEntity.cs
    ├── Entity/RefreshTokenEntity.cs
    └── Repositories/IRepositories.cs
```

## 关键接口签名

```csharp
[HttpGet("apps")] Task<IActionResult> GetApps();
[HttpPost("apps")] Task<IActionResult> CreateApp(AdminCreateAppRequest request);
[HttpPut("apps/{appId}/callback")] Task<IActionResult> UpdateCallback(string appId, AdminUpdateCallbackRequest request);
[HttpDelete("apps/{appId}")] Task<IActionResult> DeleteApp(string appId);
[HttpPost("apps/{appId}/reset-secret")] Task<IActionResult> ResetAppSecret(string appId);
[HttpPost("tokens/revoke")] Task<IActionResult> RevokeRefreshToken(AdminRevokeRefreshTokenRequest request);
[HttpGet("audit-logs")] Task<IActionResult> GetAuditLogs(...);
```

## 依赖的数据库表

- [app_registrations](../../database/tables/app_registrations.md)
- [refresh_tokens](../../database/tables/refresh_tokens.md)
- [audit_logs](../../database/tables/audit_logs.md)

## 数据流/调用链

### 创建应用流程

```
Request (appName)
  │
  ▼
Generate AppId = Guid.NewGuid().ToString("N")   ← 32 位十六进制，无连字符
  │
  ▼
Generate AppSecret = Base64(RandomNumberGenerator.GetBytes(32))   ← 32 字节密码学安全随机
  │
  ▼
AppSecretHash = BCrypt.HashPassword(AppSecret)   ← 仅存储哈希
  │
  ▼
Save to DB (AppRegistration: AppId, AppName, AppSecretHash, IsActive=true)
  │
  ▼
Response 200 { AppId, AppSecret (明文) }   ← 明文仅此一次返回
```

## 关键设计决策

| 决策 | 说明 |
|------|------|
| AppSecret 仅在创建和重置时返回明文 | 明文 AppSecret 从不存储在数据库中，仅在创建/重置时返回给调用方一次，之后无法再获取 |
| AppId 格式 | Guid.NewGuid().ToString("N")，生成 32 位十六进制字符串（无连字符），作为应用唯一标识 |
| TTL 处理逻辑 | TtlSeconds=-1 → CallbackExpiresAt=null（永不过期）；TtlSeconds>0 → ExpiresAt=now+TtlSeconds；其余 → ExpiresAt=now+3600s（默认 1 小时） |
