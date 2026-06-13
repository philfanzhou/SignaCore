# 统一 Token 获取 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为业务系统的用户，我希望通过统一的接口使用不同的登录方式进行认证，以便获得访问业务系统的 JWT 令牌。

补充约束：回调失败不阻塞登录；刷新令牌一次性使用；密码登录有防暴力破解保护。

## 功能要求清单

- [ ] FR-01: 接受 grant_type 参数，分发到对应的验证器
- [ ] FR-02: 验证网关身份（AppId/AppSecret），无效时拒绝请求
- [ ] FR-03: 密码登录验证（PasswordValidator）
- [ ] FR-04: 短信验证码登录验证（SmsValidator），支持自动注册
- [ ] FR-05: 微信 code 登录验证（WechatValidator）
- [ ] FR-06: 刷新令牌验证（RefreshTokenValidator），AppId 匹配检查
- [ ] FR-07: 构建基本 Claims（sub, jti, iat, name, nickname, auth_method）
- [ ] FR-08: 回调权限注入（如有 CallbackUrl）
- [ ] FR-09: 使用 RSA 密钥签发 JWT
- [ ] FR-10: 生成刷新令牌并持久化
- [ ] FR-11: 记录登录审计日志
- [ ] FR-12: 更新账户登录统计信息

## 详细的验收标准

### AC-FR-01: Grant Type 分发

- **Given** 一个 GetToken 请求
- **When** grant_type 为 "password" / "sms" / "wechat_code" / "refresh_token"
- **Then** 请求被分发到对应的验证器

- **Given** 一个 GetToken 请求
- **When** grant_type 为不支持的值
- **Then** 返回 success=false, message="unsupported_grant_type"

### AC-FR-02: 网关验证

- **Given** 请求包含 AppId 和 AppSecret
- **When** AppId 未注册
- **Then** 返回 success=false, message="AppId not registered"

- **Given** 请求包含 AppId 和 AppSecret
- **When** AppSecret 不匹配
- **Then** 返回 success=false, message="AppSecret mismatch"

### AC-FR-03: 密码登录

- **Given** 正确的用户名和密码
- **When** 账户活跃且未锁定
- **Then** 返回 success=true, access_token, refresh_token, user_info

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

- **Given** 有效的 refresh_token
- **When** AppId 匹配
- **Then** 旧 token 被撤销，返回新的 access_token 和 refresh_token

- **Given** refresh_token 的 AppId 与请求 AppId 不匹配
- **When** 验证
- **Then** 返回 success=false, message="Refresh token is not valid for this application"

### AC-FR-08: 回调权限注入

- **Given** 登录成功且 AppId 对应的业务系统有 CallbackUrl
- **When** 回调成功返回 roles 和 permissions
- **Then** JWT 中包含对应的 role 和 permission claims

- **Given** 登录成功且回调失败
- **When** 回调超时或异常
- **Then** JWT 仅包含基本身份信息，登录不被阻塞

## 非功能需求

| 类别 | 需求 |
|------|------|
| 性能 | 登录请求耗时通过 auth.login.duration 指标监控 |
| 安全 | 密码使用 BCrypt 哈希验证；AppSecret 使用 BCrypt.Verify |
| 安全 | 回调超时 2 秒；JWKS 端点速率限制 60 次/分钟 |
| 可靠性 | 回调失败降级为基本 JWT，不阻塞登录 |
| 可观测性 | 记录登录成功/失败指标、审计日志、结构化日志 |

## 测试策略

- 单元测试覆盖各 Validator 的验证逻辑
- 集成测试覆盖 AuthServiceImpl 的完整登录流程
- 错误路径测试：无效凭证、锁定账户、过期令牌、回调失败
