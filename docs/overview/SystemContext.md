# 系统上下文 (SystemContext)

## 服务定位

QuantumZhou.Identity 是统一身份认证与权限管理中心（Identity Provider），基于 .NET 10 构建。负责集中处理用户认证、签发标准化 JWT、管理业务系统注册和动态权限注入。

## 上下游调用关系

```
                    ┌──────────────────┐
                    │  Admin Frontend  │
                    │  (Vue 3 + Vite)  │
                    └────────┬─────────┘
                             │ HTTP (Cookie Auth) :5010
                             ▼
┌──────────┐    HTTP     ┌──────────────────────────┐    HTTP Callback    ┌──────────────────┐
│  Gateway │───────────▶│   QuantumZhou.Identity   │───────────────────▶│ Business Services │
│ (WebApi) │◀───────────│                          │◀───────────────────│ (各业务 BFF)      │
└──────────┘  JWT Token │  HTTP :5002 (业务/认证)  │   Roles/Perms      │                   │
                         │  HTTP :5010 (Admin API)  │                    └──────────────────┘
                         └──────────┬───────────────┘
                                    │
                         ┌──────────▼───────────┐
                         │    PostgreSQL        │
                         └──────────────────────┘

┌──────────────┐  HTTP (Bearer JWT)   ┌──────────────────┐
│  Downstream  │◀─────────────────────│ /.well-known/jwks│
│  Microservices│  Local verification │ (Public Key)      │
└──────────────┘                      └──────────────────┘
```

## 上游调用方

| 调用方 | 协议 | 用途 |
|--------|------|------|
| Gateway / WebApi | HTTP | `POST /api/auth/token` 用户登录认证 |
| Gateway / WebApi | HTTP | `POST /api/auth/callback/register` 注册业务系统回调 |
| Gateway / WebApi | HTTP | `POST /api/auth/revoke` 吊销刷新令牌 |
| Admin Frontend (Vue) | HTTP + Cookie | 调用 Admin API 进行用户/应用/令牌管理 |
| Gateway API Consumer | HTTP + AppId/AppSecret Header | 调用 Gateway API 查询用户信息 |

## 下游依赖

| 依赖 | 类型 | 用途 |
|------|------|------|
| PostgreSQL | 数据库 | 存储账户、凭证、令牌、密钥等数据 |
| Consul（可选） | 服务发现 + 配置中心 | 非密钥配置集中管理、服务注册与健康检查；Consul 不可用时自动降级到本地缓存，不影响服务可用性 |
| WeChat Open Platform API | HTTP | 微信登录时调用 `jscode2session` 获取 OpenId |
| Business Service Callback | HTTP | 登录后回调业务系统获取用户角色和权限 |

## 服务边界

- **本服务负责**：用户认证、JWT 签发、刷新令牌管理、业务系统注册、回调权限注入、密钥管理、审计日志
- **本服务不负责**：用户业务数据管理、业务权限定义（由业务系统通过回调提供）、前端路由和页面渲染
- **通信协议**：HTTP REST（业务认证、管理 API、OIDC Discovery、JWKS、健康检查）
- **端口分配**：HTTP 5002（业务/认证）、HTTP 5010（Admin API）
