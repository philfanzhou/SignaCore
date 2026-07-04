# 集成矩阵 (Integration)

## 集成总表

| 集成点 | 方向 | 接口类型 | 协议 | 说明 |
|--------|------|----------|------|------|
| Auth API (api/auth/*) | 入 | HTTP REST | HTTP/1.1,2 | 统一认证接口（token/sms-code/revoke/callback） |
| Admin API (api/admin/*) | 入 | HTTP REST | HTTP/1.1,2 | 管理员操作接口（Cookie Auth） |
| Gateway API (api/gateway/*) | 入 | HTTP REST | HTTP/1.1,2 | 网关用户查询接口（AppId/AppSecret Auth） |
| Profile API (api/profile/*) | 入 | HTTP REST | HTTP/1.1,2 | 用户个人信息接口（JWT Bearer Auth） |
| OIDC Discovery (/.well-known/openid-configuration) | 入 | HTTP REST | HTTP/1.1,2 | OIDC 发现文档 |
| JWKS (/.well-known/jwks) | 入 | HTTP REST | HTTP/1.1,2 | JWT 公钥端点 |
| Health Check (/health) | 入 | HTTP REST | HTTP/1.1,2 | 健康检查端点 |
| Prometheus Metrics (/metrics) | 入 | HTTP REST | HTTP/1.1,2 | Prometheus 指标端点 |
| WeChat API (/sns/jscode2session) | 出 | HTTP | HTTPS | 微信登录获取 OpenId |
| Business Service Callback | 出 | HTTP | HTTP/HTTPS | 登录后获取用户角色和权限 |

## Client SDK 集成（已废弃）

> `QuantumZhou.Identity.Client` SDK 已停止维护，源码已移除，仅保留历史构建产物。业务系统应改为直接调用 Identity 的 HTTP API（`POST /api/auth/token` 等），详见 [GetToken SPEC](../modules/Auth/GetToken/02-SPEC.md)。

业务服务曾通过 `QuantumZhou.Identity.Client` 项目引用接入 Identity 认证。Client SDK 内部使用 gRPC 调用 Identity 的 `GetToken` 接口，对外封装为 HTTP 端点（login/refresh/me/logout）。

### 调用链路（历史，已废弃）

```
业务前端 → 业务后端 (Client SDK AuthEndpoints) → Identity (gRPC GetToken)
```

### 当前推荐调用链路

```
业务前端 → 业务后端 (AuthController) → Identity (HTTP POST /api/auth/token)
```

### 曾接入服务

| 服务 | 接入方式 | 认证端点路径 |
|------|---------|-------------|
| ruoyu.doclibrary | Identity.Client 项目引用 | `/admin/auth/*` |

## 失败语义总结

### 出方向：WeChat API 调用失败

- **行为**：`WechatApiClient.CodeToSessionAsync` 捕获所有异常，返回 `null`
- **影响**：微信登录验证失败，返回 "WeChat authentication failed"
- **降级策略**：无降级，直接拒绝登录

### 出方向：Business Service Callback 调用失败

- **行为**：`CallbackService.FetchExternalClaimsAsync` 捕获所有异常（含超时），返回空 Claims 列表
- **影响**：JWT 中不包含该业务系统的角色和权限信息
- **降级策略**：继续签发只包含基本身份信息的 JWT，不阻塞登录流程
- **超时设置**：2 秒（`IdentityConstants.CallbackTimeoutSeconds`）

### 入方向：gRPC 请求失败

- **速率限制**：超过限制返回 `StatusCode.ResourceExhausted`
- **异常处理**：`ExceptionHandlingInterceptor` 将未处理异常转换为 gRPC 状态码
  - `ArgumentException` → `StatusCode.InvalidArgument`
  - `InvalidOperationException` → `StatusCode.FailedPrecondition`
  - 其他 → `StatusCode.Internal`
