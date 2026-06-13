# 回调注册 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Contract/Protos/auth.proto              # RegisterCallback RPC 定义
├── Service/AuthServiceImpl.cs              # RegisterCallback 实现
└── Database/
    ├── Entity/AppRegistrationEntity.cs     # 应用注册实体
    └── Repositories/IRepositories.cs       # IAppRegistrationRepository
```

## 关键接口签名

```csharp
// gRPC
rpc RegisterCallback(RegisterCallbackRequest) returns (RegisterCallbackResponse);

message RegisterCallbackRequest {
  string app_id = 1;
  string app_secret = 2;
  string callback_url = 3;
  int32 ttl_seconds = 4;
}
```

## 依赖的数据库表

- [app_registrations](../../database/tables/app_registrations.md) — 更新 CallbackUrl 和 CallbackExpiresAt

## 数据流

```
RegisterCallback Request
    │
    ▼
Validate AppId/AppSecret not empty
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
