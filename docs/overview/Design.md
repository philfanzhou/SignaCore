# 服务级架构 (Design)

## 分层说明

```
┌─────────────────────────────────────────────────────┐
│                      Host                            │
│  Controllers (Admin/Gateway/Profile) + SPA Hosting   │
├─────────────────────────────────────────────────────┤
│                     Service                          │
│  AuthController（HTTP REST）                          │
├─────────────────────────────────────────────────────┤
│                     Domain                           │
│  Validators + TokenService + KeyManager + Callback   │
├─────────────────────────────────────────────────────┤
│                    Database                          │
│  DbContext + Repositories + Entities + Migrations    │
└─────────────────────────────────────────────────────┘
```

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| .NET | 8.0 | 运行时 |
| ASP.NET Core | 8.0 | Web 框架 |
| gRPC | 内置 | 服务间通信 |
| EF Core | 8.0 | ORM |
| PostgreSQL | 12+ | 生产数据库 |
| SQLite | 内置 | 开发数据库 |
| BCrypt.Net | - | 密码哈希 |
| OpenTelemetry | - | 可观测性 |
| JWT | System.IdentityModel | 令牌签发 |
| Vue 3 + Vite | - | 管理前端 |

## 项目依赖关系

```
Database ← Domain ← Service ← Host
                ↑         │
                └─────────┘
```

| 项目 | 依赖 |
|------|------|
| QuantumZhou.Identity.Database | 无 |
| QuantumZhou.Identity.Domain | Database |
| QuantumZhou.Identity.Service | Domain |
| QuantumZhou.Identity.Host | Service, Domain, Database |

## Client SDK

`QuantumZhou.Identity.Client` 是提供给业务服务接入 Identity 认证的 SDK 类库，封装了 gRPC 客户端注册、JWT Bearer 认证配置和认证端点（login/refresh/me/logout），使业务服务只需 3 行代码即可完成认证接入。

### 接入方式

```csharp
// Program.cs
builder.Services.AddIdentityClient(builder.Configuration);
// ...
app.UseIdentityClient();
app.MapIdentityAuthEndpoints();
```

```json
// appsettings.json
{
  "Identity": {
    "GrpcEndpoint": "http://localhost:5001",
    "AppId": "your_app_id",
    "AppSecret": ""
  },
  "Jwt": {
    "Issuer": "QuantumZhou.Identity",
    "Audience": "QuantumZhou.microservices",
    "JwksEndpoint": "http://localhost:5002/.well-known/jwks"
  }
}
```

### 提供的端点

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| POST | `/admin/auth/login` | AllowAnonymous | 用户名密码登录，代理 gRPC GetToken |
| POST | `/admin/auth/refresh` | AllowAnonymous | RefreshToken 刷新 |
| GET | `/admin/auth/me` | 需认证 | 获取当前用户信息（从 JWT Claims 读取） |
| POST | `/admin/auth/logout` | 需认证 | 登出（前端清除 Token） |

### 关键源文件

| 文件 | 用途 |
|------|------|
| [IdentityClientOptions.cs](../../backend/Client/IdentityClientOptions.cs) | 配置项定义 |
| [ServiceCollectionExtensions.cs](../../backend/Client/ServiceCollectionExtensions.cs) | AddIdentityClient() 扩展方法 + JwksFetcher |
| [ApplicationBuilderExtensions.cs](../../backend/Client/ApplicationBuilderExtensions.cs) | UseIdentityClient() + MapIdentityAuthEndpoints() |
| [AuthEndpoints.cs](../../backend/Client/AuthEndpoints.cs) | 认证端点实现 |

### JWKS 获取机制

JWT 验证需要从 Identity 服务获取 JWKS 公钥。SDK 使用 `JwksFetcher` 类（普通 HttpClient）手动获取并解析 JWKS，不依赖 `ConfigurationManager`（后者在 Docker 容器环境中存在静默失败问题）。密钥缓存 30 分钟，失败不缓存，下次请求重试。

## 协议选型决策

### 背景

Identity 服务最初使用 gRPC 作为内部服务间通信协议，HTTP REST 仅用于管理 API、OIDC Discovery、JWKS 和健康检查。经实际运行分析，发现 gRPC 在本场景中带来不必要的客户端复杂度：

- **调用频率极低**：gRPC `GetToken` 仅在登录/SSO/令牌刷新时调用，每次登录 1 次；每次请求的认证校验走 JWT 本地验证（JWKS 缓存 30 分钟），不调用 Identity。gRPC 的性能优势无处发挥。
- **客户端复杂度高**：调用方需引入 proto 契约依赖、gRPC 通道配置、`RpcException` 处理。User Portal 和 Teacher Portal 的 gRPC 客户端注册代码几乎完全重复。
- **SDK 形同虚设**：Identity Client SDK 只有 DocLibrary 一个消费者，三个 Portal 均未使用。
- **OIDC 发现文档已声明 HTTP 端点**：`/.well-known/openid-configuration` 声明 `token_endpoint = /api/auth/token`，但该 HTTP 端点实际不存在——说明设计意图是 HTTP，只是未落地。

### 决策

**Phase 1（已完成）**：在 Identity 服务新增 HTTP `/api/auth/*` 端点，与 gRPC 并存。各调用方逐步切换到 HTTP 调用。

**Phase 2（当前执行）**：删除 gRPC 相关代码，包括：
- `auth.proto` 与 `QuantumZhou.Identity.Contract` 项目
- `AuthServiceImpl`（gRPC 服务实现）
- 3 个 gRPC 拦截器（`CorrelationIdInterceptor`、`RateLimitingInterceptor`、`ExceptionHandlingInterceptor`）
- `QuantumZhou.Identity.Client` SDK
- gRPC 端口 5001

### HTTP 端点设计

| 端点 | HTTP 方法 | 对应 gRPC 方法 | 认证方式 | 说明 |
|------|-----------|---------------|---------|------|
| `/api/auth/token` | POST | `GetToken` | AppId/AppSecret 头（可选） | OAuth2 grant_type 模式，支持 password/sms/wechat_code/refresh_token |
| `/api/auth/sms-code` | POST | `RequestSmsCode` | AppId/AppSecret 头（可选） | 请求短信验证码 |
| `/api/auth/revoke` | POST | `RevokeRefreshToken` | 无（需持有 refresh_token） | 吊销刷新令牌 |
| `/api/auth/callback/register` | POST | `RegisterCallback` | AppId/AppSecret 头 | 注册业务系统权限回调 URL |

### 兼容性保证

- Phase 1 期间 gRPC 端点 5001 继续保留，不影响现有未迁移的调用方
- HTTP 端点与 gRPC 端点共享同一套 Domain 层逻辑，行为完全一致
- 客户端可按自身节奏迁移到 HTTP

## HTTP 中间件

Phase 2 移除 gRPC 拦截器后，HTTP 路径的横切关注点由 ASP.NET Core 中间件承担：

| 中间件 | 来源 | 替代的 gRPC 拦截器 | 说明 |
|--------|------|--------------------|------|
| `CorrelationIdMiddleware` | 已存在 | `CorrelationIdInterceptor` | 从请求头 `x-correlation-id` 读取或新建 CorrelationId，写入 `HttpContext.Items` 并通过 `ILogger.BeginScope` 注入日志上下文，响应头回写 |
| `AddRateLimiter` / `UseRateLimiter` | .NET 8 内置 | `RateLimitingInterceptor` | 使用 .NET 8 内置速率限制框架，配置 `RateLimiterOptions` 替代自定义 gRPC 限流拦截器 |
| `ExceptionHandlingMiddleware` | 新增 | `ExceptionHandlingInterceptor` | 统一捕获未处理异常，转换为 HTTP 状态码和 JSON 错误响应（详见 [ErrorHandling.md](../development/ErrorHandling.md)） |

## 详细设计

各功能点的详细设计见 [modules/](../modules/README.md) 目录。
