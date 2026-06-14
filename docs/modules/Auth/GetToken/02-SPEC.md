# 统一 Token 获取 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为业务系统的用户，我希望通过统一的接口使用不同的登录方式进行认证，以便获得访问业务系统的 JWT 令牌。

补充约束：回调失败不阻塞登录；刷新令牌一次性使用；密码登录有防暴力破解保护。

## 功能要求清单

- [ ] FR-01: 接受 grant_type 参数，分发到对应的验证器
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

- **Given** 请求包含有效的 AppId 和 AppSecret
- **When** 验证成功
- **Then** GatewayAuthResult 携带 AppRegistrationEntity，后续流程无需二次查询

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
- 单元测试覆盖 RequestSmsCode 空手机号/无效网关/正常发送
- 单元测试覆盖 RegisterCallback 无效 CallbackUrl 拒绝
- 集成测试覆盖 AuthServiceImpl 的完整登录流程
- 错误路径测试：无效凭证、锁定账户、过期令牌、回调失败
