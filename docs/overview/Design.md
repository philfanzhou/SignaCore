# 服务级架构 (Design)

## 分层说明

```
┌─────────────────────────────────────────────────────┐
│                      Host                            │
│  Controllers (Token/SmsCode/TokenRevocation/         │
│   CallbackRegistration/Admin/Gateway/Profile)        │
│  + Middleware + SPA Hosting                          │
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
| EF Core | 8.0 | ORM |
| PostgreSQL | 12+ | 数据库 |
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

## 协议选型决策

### 背景

Identity 服务最初使用 gRPC 作为内部服务间通信协议，HTTP REST 仅用于管理 API、OIDC Discovery、JWKS 和健康检查。经实际运行分析，发现 gRPC 在本场景中带来不必要的客户端复杂度：

- **调用频率极低**：gRPC `GetToken` 仅在登录/SSO/令牌刷新时调用，每次登录 1 次；每次请求的认证校验走 JWT 本地验证（JWKS 缓存 30 分钟），不调用 Identity。gRPC 的性能优势无处发挥。
- **客户端复杂度高**：调用方需引入 proto 契约依赖、gRPC 通道配置、`RpcException` 处理。User Portal 和 Teacher Portal 的 gRPC 客户端注册代码几乎完全重复。
- **SDK 形同虚设**：Identity Client SDK 只有 DocLibrary 一个消费者，三个 Portal 均未使用。
- **OIDC 发现文档已声明 HTTP 端点**：`/.well-known/openid-configuration` 声明 `token_endpoint = /api/auth/token`，但该 HTTP 端点实际不存在——说明设计意图是 HTTP，只是未落地。

### 决策

**Phase 1（已完成）**：在 Identity 服务新增 HTTP `/api/auth/*` 端点，与 gRPC 并存。各调用方逐步切换到 HTTP 调用。

**Phase 2（已完成）**：删除 gRPC 相关代码，包括：
- `auth.proto` 与 `QuantumZhou.Identity.Contract` 项目
- `AuthServiceImpl`（gRPC 服务实现）
- 3 个 gRPC 拦截器（`CorrelationIdInterceptor`、`RateLimitingInterceptor`、`ExceptionHandlingInterceptor`）
- `QuantumZhou.Identity.Client` SDK
- gRPC 端口 5001

### HTTP 端点设计

> Phase 2 已完成 gRPC 移除，下表"对应 gRPC 方法"列仅供历史迁移参考，gRPC 服务已不存在。

| 端点 | HTTP 方法 | 原 gRPC 方法（已移除） | 认证方式 | 说明 |
|------|-----------|----------------------|---------|------|
| `/api/auth/token` | POST | `GetToken` | AppId/AppSecret 头（可选） | OAuth2 grant_type 模式，支持 password/sms/wechat_code/refresh_token |
| `/api/auth/sms-code` | POST | `RequestSmsCode` | AppId/AppSecret 头（可选） | 请求短信验证码 |
| `/api/auth/revoke` | POST | `RevokeRefreshToken` | 无（需持有 refresh_token） | 吊销刷新令牌 |
| `/api/auth/callback/register` | POST | `RegisterCallback` | AppId/AppSecret 头 | 注册业务系统权限回调 URL |

### 兼容性保证

- gRPC 协议已于 Phase 2 完全移除（端口 5001、proto 契约、gRPC 服务实现、Client SDK 均已移除）
- HTTP 端点与原 gRPC 端点共享同一套 Domain 层逻辑，行为完全一致
- 所有调用方已完成迁移，Identity 服务现为纯 HTTP 服务

## HTTP 中间件

Phase 2 移除 gRPC 拦截器后，HTTP 路径的横切关注点由 ASP.NET Core 中间件承担：

| 中间件 | 来源 | 替代的 gRPC 拦截器 | 说明 |
|--------|------|--------------------|------|
| `CorrelationIdMiddleware` | 已存在 | `CorrelationIdInterceptor` | 从请求头 `x-correlation-id` 读取或新建 CorrelationId，写入 `HttpContext.Items` 并通过 `ILogger.BeginScope` 注入日志上下文，响应头回写 |
| `AddRateLimiter` / `UseRateLimiter` | .NET 8 内置 | `RateLimitingInterceptor` | 使用 .NET 8 内置速率限制框架，配置 `RateLimiterOptions` 替代自定义 gRPC 限流拦截器 |
| `ExceptionHandlingMiddleware` | 新增 | `ExceptionHandlingInterceptor` | 统一捕获未处理异常，转换为 HTTP 状态码和 JSON 错误响应（详见 [ErrorHandling.md](../development/ErrorHandling.md)） |

## 详细设计

各功能点的详细设计见 [modules/](../modules/README.md) 目录。
