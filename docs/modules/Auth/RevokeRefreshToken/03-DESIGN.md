# 刷新令牌吊销 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Host/Controllers/AuthController.cs      # POST /api/auth/revoke HTTP 端点
├── Host/Models/AuthModels.cs               # RevokeRequest / RevokeResponse DTO
├── Domain/Services/RefreshTokenService.cs  # 吊销逻辑（RevokeAsync）
└── Database/
    ├── Entity/RefreshTokenEntity.cs        # 刷新令牌实体
    └── Repositories/IRefreshTokenRepository.cs
```

## 关键接口签名

```csharp
// HTTP 端点（AuthController）
[HttpPost("revoke")]
public async Task<ActionResult<RevokeResponse>> RevokeRefreshToken(
    [FromBody] RevokeRequest request)

// 请求/响应 DTO（见 AuthModels.cs）
public sealed class RevokeRequest { string RefreshToken; }
public sealed class RevokeResponse { bool Success; }
```

## 依赖的数据库表

- [refresh_tokens](../../../database/tables/refresh_tokens.md) — 查找令牌并标记 IsRevoked

## 数据流

```
RevokeRefreshToken Request
    │
    ▼
Validate refresh_token not empty
    │
    ▼
RefreshTokenRepository.GetByTokenValueAsync
    │
    ▼
Set IsRevoked = true
    │
    ▼
SaveChangesAsync
    │
    ▼
RevokeResponse { Success = true/false }
```
