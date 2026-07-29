# 统一 Token 获取 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为业务系统的用户，我希望通过统一的接口使用不同的登录方式进行认证，以便获得访问业务系统的 JWT 令牌。

补充约束：回调失败不阻塞登录；刷新令牌一次性使用；密码登录有防暴力破解保护。

## 功能要求清单

- [ ] FR-01: 接受 grantType 参数，分发到对应的验证器
- [ ] FR-02: 验证网关身份（AppId/AppSecret），无效时拒绝请求；验证成功返回 App 实体，避免二次查询
- [ ] FR-03: 密码登录验证（PasswordValidator）
- [ ] FR-04: 短信验证码登录验证（SmsValidator），支持自动注册
- [ ] FR-05: 微信 code 登录验证（WechatValidator）
- [ ] FR-06: 刷新令牌验证（RefreshTokenValidator），AppId 匹配检查
- [ ] FR-07: 构建基本 Claims（sub, jti, iat, name, nickname, auth_method）
- [ ] FR-08: 回调权限注入（如有 CallbackUrl），对回调返回的 Claim 施加数量和长度限制
- [ ] FR-09: 使用 RSA 密钥签发 JWT
- [ ] FR-10: 生成刷新令牌并持久化
- [ ] FR-11: 记录登录审计日志
- [ ] FR-12: 更新账户登录统计信息
- [ ] FR-13: 请求短信验证码（RequestSmsCode），支持可选网关验证
- [ ] FR-14: HTTP `POST /api/auth/token` 端点，与 gRPC `GetToken` 行为一致
- [ ] FR-15: HTTP `POST /api/auth/sms-code` 端点，与 gRPC `RequestSmsCode` 行为一致
- [ ] FR-16: HTTP `POST /api/auth/revoke` 端点，与 gRPC `RevokeRefreshToken` 行为一致
- [ ] FR-17: HTTP `POST /api/auth/callback/register` 端点，与 gRPC `RegisterCallback` 行为一致

## HTTP API 规范（Phase 1 新增）

### POST /api/auth/token

**认证**：可选 AppId/AppSecret 请求头（`X-Admin-AppId` / `X-Admin-AppSecret`），与 gRPC 请求体中的 `appId` / `appSecret` 等效。

**请求体**（JSON）：

```json
{
  "grantType": "password | sms | wechat_code | refresh_token",
  "username": "string (grantType=password 时必填)",
  "password": "string (grantType=password 时必填)",
  "phone": "string (grantType=sms 时必填)",
  "code": "string (grantType=sms 或 wechat_code 时必填)",
  "refreshToken": "string (grantType=refresh_token 时必填)"
}
```

> AppId/AppSecret 通过请求头传递，不放在请求体中（与 GatewayController 保持一致）。

**响应体**（200 OK，业务成功/失败均返回 200，通过 `success` 字段区分）：

```json
{
  "success": true,
  "message": "",
  "accessToken": "eyJ...",
  "refreshToken": "rt_...",
  "expiresIn": 7200,
  "expiresAt": 1719900000,
  "userInfo": {
    "userId": "uuid",
    "username": "alice",
    "phone": "",
    "email": "",
    "clientType": "",
    "authMethod": "Password",
    "roles": ["student"],
    "permissions": ["read"]
  }
}
```

> 注：`userInfo.phone`/`email`/`clientType` 当前实现不填充（恒为空字符串），`AuthController` 仅设置 UserId/Username/AuthMethod/Roles/Permissions。

### POST /api/auth/sms-code

**请求头**：`X-Admin-AppId` / `X-Admin-AppSecret`（可选，用于网关验证）。

**请求体**：`{ "phone": "13800138000" }`

**响应体**：`{ "success": true, "message": "" }`

### POST /api/auth/revoke

**请求体**：`{ "refreshToken": "rt_..." }`

**响应体**：`{ "success": true }`

### POST /api/auth/callback/register

**请求头**：`X-Admin-AppId` / `X-Admin-AppSecret`（必填）。

**请求体**：`{ "callbackUrl": "http://...", "ttlSeconds": 3600 }`

**响应体**：`{ "success": true, "message": "", "expiresAt": 1719900000 }`

## 详细的验收标准

### AC-FR-01: Grant Type 分发

- **Given** 一个 GetToken 请求
- **When** grantType 为 "password" / "sms" / "wechat_code" / "refresh_token"
- **Then** 请求被分发到对应的验证器

- **Given** 一个 GetToken 请求
- **When** grantType 为不支持的值
- **Then** 返回 success=false, message="unsupported_grant_type"

### AC-FR-02: 网关验证

- **Given** 请求包含 AppId 和 AppSecret
- **When** AppId 未注册
- **Then** 返回 success=false, message="AppId not registered"

- **Given** 请求包含 AppId 和 AppSecret
- **When** AppSecret 不匹配
- **Then** 返回 success=false, message="AppSecret mismatch"

- **Given** 请求包含有效的 AppId 和 AppSecret
- **When** 验证成功
- **Then** GatewayAuthResult 携带 AppRegistrationEntity，后续流程无需二次查询

### AC-FR-03: 密码登录

- **Given** 正确的用户名和密码
- **When** 账户活跃且未锁定
- **Then** 返回 success=true, accessToken, refreshToken, userInfo

- **Given** 错误的密码
- **When** 连续失败未达上限
- **Then** 返回 success=false, message="Wrong username or password"

- **Given** 连续失败达到 5 次
- **When** 锁定未过期
- **Then** 返回 success=false, message 包含锁定截止时间

### AC-FR-04: 短信登录

- **Given** 正确的手机号和验证码
- **When** 手机号未注册
- **Then** 自动创建账户和 UserLogin 绑定，返回 token

- **Given** 正确的手机号和验证码
- **When** 手机号已注册
- **Then** 返回 token

- **Given** 错误或过期的验证码
- **When** 验证失败
- **Then** 返回 success=false, message="Wrong or expired verification code"

### AC-FR-05: 微信登录

- **Given** 有效的微信 code
- **When** OpenId 已绑定账户
- **Then** 返回 token

- **Given** 有效的微信 code
- **When** OpenId 未绑定任何账户
- **Then** 返回 success=false, message="WeChat is not bound to any account"

### AC-FR-06: 刷新令牌

- **Given** 有效的 refreshToken
- **When** AppId 匹配
- **Then** 旧 token 被撤销，返回新的 accessToken 和 refreshToken

- **Given** refreshToken 的 AppId 与请求 AppId 不匹配
- **When** 验证
- **Then** 返回 success=false, message="Refresh token is not valid for this application"

- **Given** `AdminBootstrap:Username` 配置非空，refresh_token 对应的已验证账户与该配置对应的密码账户是同一账户
- **When** 调用 GetToken(grantType="refresh_token")
- **Then** 新 JWT 包含 `role=admin`，且 `role=admin` 在 claims 中只出现一次

- **Given** 普通账户的 refresh_token，且请求体恶意附带 `username=admin`（与 `AdminBootstrap:Username` 相同）
- **When** 调用 GetToken(grantType="refresh_token")
- **Then** 新 JWT **不**包含 `role=admin`（refresh grant 不读取请求体 `username`，只比较已验证的 `AccountEntity.Id`）

- **Given** SMS/微信 grant 对应的账户恰好是 bootstrap account
- **When** 调用 GetToken(grantType="sms" 或 "wechat_code")
- **Then** 不触发 bootstrap admin 注入，JWT 角色完全由 callback 决定

### AC-FR-08: 回调权限注入

- **Given** 登录成功且 AppId 对应的业务系统有 CallbackUrl
- **When** 回调成功返回 roles 和 permissions
- **Then** JWT 中包含对应的 role 和 permission claims

- **Given** 登录成功且回调失败
- **When** 回调超时或异常
- **Then** JWT 仅包含基本身份信息，登录不被阻塞

- **Given** 回调返回的 roles 或 permissions 数量超过 50
- **When** 解析回调响应
- **Then** 仅取前 50 个，记录 Warning 日志

- **Given** 回调返回的 CustomClaims 包含不在白名单中的类型
- **When** 解析回调响应
- **Then** 跳过不允许的类型，记录 Warning 日志；白名单：department, class_name, grade, subject, school, organization, title

- **Given** 回调返回的 Claim 值长度超过 256 字符
- **When** 解析回调响应
- **Then** 跳过该 Claim，记录 Warning 日志

### AC-FR-13: 请求短信验证码

- **Given** RequestSmsCodeRequest 且 phone 为空
- **When** 调用 RequestSmsCode
- **Then** 返回 success=false, message="Phone number is required"

- **Given** RequestSmsCodeRequest 且包含 AppId/AppSecret
- **When** 网关验证失败
- **Then** 返回 success=false, message 为网关验证错误信息

- **Given** RequestSmsCodeRequest 且 phone 有效
- **When** 调用成功
- **Then** 通过 OtpService 生成验证码并通过 ISmsSender 发送，返回 success=true

- **Given** 生产环境
- **When** 调用 RequestSmsCode
- **Then** ISmsSender 为 ThrowingSmsSender，未配置真实 SMS 提供商时抛出 InvalidOperationException

## 非功能需求

| 类别 | 需求 |
|------|------|
| 性能 | 登录请求耗时通过 auth.login.duration 指标监控 |
| 安全 | 密码使用 BCrypt 哈希验证；AppSecret 使用 BCrypt.Verify |
| 安全 | 回调超时 2 秒；JWKS 端点速率限制 60 次/分钟 |
| 安全 | 回调返回 Claim 数量限制：每种类型最多 50 个，值长度不超过 256 字符 |
| 安全 | CustomClaims 仅允许白名单类型：department, class_name, grade, subject, school, organization, title |
| 安全 | Bootstrap admin refresh 角色保持：refresh_token grant 使用已验证的 `AccountEntity.Id` 与 `AdminBootstrap:Username` 对应账户 ID 比较；**不**读取 refresh 请求体 `username`，普通账户无法通过伪造 `username=admin` 提权 |
| 安全 | SMS/微信 grant 不触发 bootstrap admin 注入，bootstrap account 身份不扩大到这两类 grant |
| 安全 | 生产环境使用 ThrowingSmsSender，开发环境使用 LoggingSmsSender（掩码记录） |
| 安全 | 生产环境未配置 AdminWeb:AllowedOrigins 时不启用跨域凭据 |
| 可靠性 | 回调失败降级为基本 JWT，不阻塞登录 |
| 可靠性 | 网关验证成功后返回 App 实体，避免二次查询 |
| 可观测性 | 记录登录成功/失败指标、审计日志、结构化日志 |
| 可观测性 | OpenTelemetry OTLP 导出端点可通过配置启用 |

## 测试策略

- 单元测试覆盖各 Validator 的验证逻辑
- 单元测试覆盖 CallbackService Claim 数量/长度/类型限制
- 单元测试覆盖 CallbackUrlValidator 同步/异步验证方法
- 单元测试覆盖 LoggingSmsSender 掩码记录和 ThrowingSmsSender 抛异常
- 单元测试覆盖 GatewayValidationService 验证成功返回 App 实体
- 单元测试覆盖 AuthController 全部 4 个 action 的成功与失败分支（网关校验失败、验证器失败含 unknown 回退、OTP 锁定透传、回调注册各分支，见 `AuthControllerTests`）
- 单元测试覆盖 RefreshTokenService（签发/轮换/吊销）、DbOtpService（锁定/过期/尝试计数）、AccountLoginInfoService、WechatApiClient
- 单元测试覆盖 RequestSmsCode 空手机号/无效网关/正常发送
- 单元测试覆盖 RegisterCallback 无效 CallbackUrl 拒绝
- 集成测试覆盖 AuthController 的完整登录流程
- 错误路径测试：无效凭证、锁定账户、过期令牌、回调失败
