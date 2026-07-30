# 统一 Token 获取 — 约定与规范 (CONVENTIONS)

## 命名约定

- HTTP 端点方法名使用 PascalCase：`GetToken`、`RegisterCallback`、`RevokeRefreshToken`、`RequestSmsCode`
- grant_type 使用 snake_case：`password`、`sms`、`wechat_code`、`refresh_token`
- AuthMethod 使用 PascalCase：`Password`、`Sms`、`WeChat`、`RefreshToken`
- 常量定义在 `IdentityConstants` 中

## 日志和安全要求

- 登录成功：LogInformation，记录 AccountId、GrantType、AppId
- 登录失败：LogWarning，记录 GrantType、Reason
- 回调失败：LogWarning，记录 AppId、Url
- 回调超时：LogWarning，记录 Url
- 审计日志：通过 AuditService 记录，包含 ClientIp、UserAgent、CorrelationId

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| 用户名或密码为空 | "Username or password cannot be empty" |
| 用户名或密码错误 | "Wrong username or password" |
| 账户被锁定 | "Account is locked. Try again after {HH:mm:ss} UTC." |
| 账户被禁用 | "Account is disabled" |
| 手机号或验证码为空 | "Phone or code cannot be empty" |
| 验证码错误或过期 | "Wrong or expired verification code" |
| 微信 code 为空 | "WeChat code cannot be empty" |
| 微信认证失败 | "WeChat authentication failed" |
| 微信未绑定 | "WeChat is not bound to any account" |
| 刷新令牌为空 | "Refresh token cannot be empty" |
| 无效的刷新令牌 | "Invalid refresh token" |
| 刷新令牌已撤销 | "Refresh token has been revoked" |
| 刷新令牌已过期 | "Refresh token has expired" |
| 刷新令牌 AppId 不匹配 | "Refresh token is not valid for this application" |
| 不支持的 grant_type | "Unsupported grant_type: {grantType}" |
| AppId 未注册 | "AppId not registered" |
| AppSecret 不匹配 | "AppSecret mismatch" |
| 应用已禁用 | "App is disabled" |
| 应用注册已过期 | "App registration has expired" |
