# 刷新令牌吊销 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Contract/Protos/auth.proto              # RevokeRefreshToken RPC 定义
├── Service/AuthServiceImpl.cs              # RevokeRefreshToken 实现
└── Database/
    ├── Entity/RefreshTokenEntity.cs        # 刷新令牌实体
    └── Repositories/IRepositories.cs       # IRefreshTokenRepository
```

## 关键接口签名

```csharp
rpc RevokeRefreshToken(RevokeRefreshTokenRequest) returns (BoolResponse);

message RevokeRefreshTokenRequest {
  string refresh_token = 1;
}
```

## 依赖的数据库表

- [refresh_tokens](../../database/tables/refresh_tokens.md) — 查找令牌并标记 IsRevoked

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
BoolResponse { Success = true/false }
```
