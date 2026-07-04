# 统一 Token 获取 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：test/unit/Host/Controllers/AuthControllerTests.cs, test/PasswordValidatorTests.cs, test/RefreshTokenValidatorTests.cs, test/SmsValidatorTests.cs, test/WechatValidatorTests.cs, test/ValidatorFactoryTests.cs

## 单元测试 — Given-When-Then 格式

### UT-01 PasswordValidator 正确密码登录

- **Given** 数据库中存在用户名 "admin" 的凭证，密码哈希匹配
- **When** 调用 ValidateAsync(username="admin", password="correct")
- **Then** 返回 IsSuccess=true, Account 不为 null, AuthMethod="Password"

### UT-02 PasswordValidator 错误密码

- **Given** 数据库中存在用户名 "admin" 的凭证
- **When** 调用 ValidateAsync(username="admin", password="wrong")
- **Then** 返回 IsSuccess=false, ErrorMessage="Wrong username or password"

### UT-03 PasswordValidator 账户锁定

- **Given** 用户名 "admin" 的 LoginAttempt 已达 5 次失败且锁定未过期
- **When** 调用 ValidateAsync(username="admin", password="any")
- **Then** 返回 IsSuccess=false, ErrorMessage 包含 "locked"

### UT-04 SmsValidator 正确验证码

- **Given** OTP 服务验证通过，手机号已注册
- **When** 调用 ValidateAsync(phone="13800138000", code="123456")
- **Then** 返回 IsSuccess=true

### UT-05 SmsValidator 自动注册

- **Given** OTP 服务验证通过，手机号未注册
- **When** 调用 ValidateAsync(phone="13800138000", code="123456")
- **Then** 自动创建 Account 和 UserLogin，返回 IsSuccess=true

### UT-06 WechatValidator 有效 code

- **Given** WechatApiClient 返回有效 OpenId，OpenId 已绑定账户
- **When** 调用 ValidateAsync(wechatCode="valid_code")
- **Then** 返回 IsSuccess=true

### UT-07 WechatValidator 未绑定

- **Given** WechatApiClient 返回有效 OpenId，OpenId 未绑定
- **When** 调用 ValidateAsync(wechatCode="valid_code")
- **Then** 返回 IsSuccess=false, ErrorMessage="WeChat is not bound to any account"

### UT-08 RefreshTokenValidator 有效令牌

- **Given** 数据库中存在未撤销、未过期的 refresh_token
- **When** 调用 ValidateAsync(refreshToken="valid_token")
- **Then** 返回 IsSuccess=true

### UT-09 RefreshTokenValidator 已撤销

- **Given** 数据库中存在已撤销的 refresh_token
- **When** 调用 ValidateAsync(refreshToken="revoked_token")
- **Then** 返回 IsSuccess=false, ErrorMessage="Refresh token has been revoked"

### UT-10 ValidatorFactory 支持的 grant_type

- **Given** ValidatorFactory 已注册四种验证器
- **When** 调用 IsSupportedGrantType("password")
- **Then** 返回 true

### UT-11 ValidatorFactory 不支持的 grant_type

- **Given** ValidatorFactory 已注册四种验证器
- **When** 调用 GetValidator("unknown")
- **Then** 抛出 KeyNotFoundException

## 遗漏的测试场景

- AuthController.GetToken 的端到端测试（当前仅有单元测试）
- 回调权限注入成功/失败的集成测试
- 网关验证失败时的审计日志记录测试
- 并发刷新令牌场景测试
- SmsValidator bypass code "666666" 的行为测试
