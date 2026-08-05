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

- [app_registrations](../../../database/tables/app_registrations.md)
- [refresh_tokens](../../../database/tables/refresh_tokens.md)
- [audit_logs](../../../database/tables/audit_logs.md)

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

## 应用注册路径

应用注册有两种互补方式：

1. **Bootstrap Apps 文件预置**：首次部署时由 `DatabaseInitializer` 读取 `data/bootstrap-apps.json` 一次性预置。适用于基础应用（如各业务 BFF）的初始凭据部署。AppId 为人工指定的固定值，AppSecret 由部署脚本生成或测试凭据。
2. **Admin API 动态注册**：运行时通过 `POST /api/admin/apps` 创建。适用于生产环境业务系统的动态接入。AppId 由服务端生成（`Guid.NewGuid().ToString("N")`），AppSecret 为 32 字节密码学安全随机。

两条路径注册的 app 统一存储于 `app_registrations` 表，共享同一套校验逻辑（`GatewayValidationService`）。预置时若 AppId 已存在则跳过，保持幂等。

## 关键设计决策

| 决策 | 说明 |
|------|------|
| AppSecret 仅在创建和重置时返回明文 | 明文 AppSecret 从不存储在数据库中，仅在创建/重置时返回给调用方一次，之后无法再获取 |
| AppId 格式 | Guid.NewGuid().ToString("N")，生成 32 位十六进制字符串（无连字符），作为应用唯一标识 |
| TTL 处理逻辑 | TtlSeconds=-1 → CallbackExpiresAt=null（永不过期）；TtlSeconds>0 → ExpiresAt=now+TtlSeconds；其余 → ExpiresAt=now+3600s（默认 1 小时） |
| Bootstrap Apps 文件路径 | 默认 `/app/data/bootstrap-apps.json`，可通过 `BootstrapApps:FilePath` 配置；文件随 `data/` 目录挂载到容器（`start.sh` 挂载 `${DATA_DIR}:/app/data`）；文件不存在时跳过（INFO 日志），不影响服务启动 |
