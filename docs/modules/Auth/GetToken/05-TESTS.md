# 统一 Token 获取 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：backend/Tests/unit/Host/Controllers/TokenControllerTests.cs, backend/Tests/unit/PasswordValidatorTests.cs, backend/Tests/unit/RefreshTokenValidatorTests.cs, backend/Tests/unit/Domain/SmsValidatorTests.cs, backend/Tests/unit/Domain/WechatValidatorTests.cs, backend/Tests/unit/ValidatorFactoryTests.cs

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

### UT-12 BootstrapAdminLogin_AlwaysGetsAdminRole

- **Given** `AdminBootstrap:Username = "admin"`，密码登录 `username="admin"`
- **Given** callback 返回空 roles（模拟从某业务应用登录，该账号在那边没有任何业务角色）
- **When** 调用 GetToken
- **Then** 最终 claims 中包含 `role=admin`（bootstrap admin 绕过 callback 注入）

### UT-13 BootstrapAdminLogin_DoesNotDuplicateAdminRole

- **Given** `AdminBootstrap:Username = "admin"`，password 登录 `username="admin"`
- **Given** callback 返回 `["admin"]`（模拟从 admin_portal 登录，已在白名单）
- **When** 调用 GetToken
- **Then** 最终 claims 中 `role=admin` 只出现一次（去重检查）

### UT-14 NonBootstrapAdminLogin_NoAdminRoleInjected

- **Given** `AdminBootstrap:Username = "admin"`，password 登录 `username="regularuser"`
- **Given** callback 返回空 roles
- **When** 调用 GetToken
- **Then** 最终 claims 中不包含 `role=admin`（非 bootstrap admin 不注入）

### UT-15 BootstrapAdminLogin_EmptyConfig_SkipsInjection

- **Given** `AdminBootstrap:Username = ""`（未配置），password 登录 `username="admin"`
- **When** 调用 GetToken
- **Then** 不注入 `role=admin`（保持原行为，避免误识别）

### UT-16 BootstrapAdminLogin_CaseInsensitive

- **Given** `AdminBootstrap:Username = "admin"`，password 登录 `username="ADMIN"`（大写）
- **When** 调用 GetToken
- **Then** 注入 `role=admin`（大小写不敏感比较）

### UT-17 BootstrapAdminRefresh_PreservesAdminRoleWithoutUsername

- **Given** `AdminBootstrap:Username = "admin"`；refresh validator 返回 `bootstrapAccount`；`IAccountRepository.GetByPasswordCredentialUsernameAsync("admin")` 返回同一 `bootstrapAccount`；`request.GrantType = "refresh_token"`；`request.RefreshToken` 有值；`request.Username` 未设置
- **When** 调用 GetToken
- **Then** `response.Success = true`；生成 JWT 的 claims 包含且只包含一个 `role=admin`

### UT-18 RegularUserRefresh_WithBootstrapUsername_DoesNotReceiveAdminRole

- **Given** `AdminBootstrap:Username = "admin"`；refresh validator 返回 `regularAccount`；`IAccountRepository.GetByPasswordCredentialUsernameAsync("admin")` 返回 `bootstrapAccount`；`regularAccount.Id != bootstrapAccount.Id`；refresh 请求恶意附带 `Username = "admin"`
- **When** 调用 GetToken
- **Then** `response.Success = true`；生成 JWT 的 claims 不包含 `role=admin`

### UT-19 BootstrapAccountSmsLogin_DoesNotReceiveBootstrapAdminRole

- **Given** `AdminBootstrap:Username = "admin"`；sms grant validator 返回的账户恰好是 bootstrap account（`AccountEntity.Id` 与 `GetByPasswordCredentialUsernameAsync("admin")` 返回的账户 ID 相等）；callback 返回空 roles
- **When** 调用 GetToken(grantType="sms")
- **Then** 生成 JWT 的 claims 不包含 `role=admin`（sms grant 不触发 bootstrap admin 注入）

### UT-20 BootstrapAccountWechatLogin_DoesNotReceiveBootstrapAdminRole

- **Given** `AdminBootstrap:Username = "admin"`；wechat_code grant validator 返回的账户恰好是 bootstrap account；callback 返回空 roles
- **When** 调用 GetToken(grantType="wechat_code")
- **Then** 生成 JWT 的 claims 不包含 `role=admin`（wechat_code grant 不触发 bootstrap admin 注入）

## 遗漏的测试场景

- TokenController.GetToken 的端到端测试（当前仅有单元测试）
- 回调权限注入成功/失败的集成测试
- 网关验证失败时的审计日志记录测试
- 并发刷新令牌场景测试
- SmsValidator 绕过白名单的集成测试（单元测试已覆盖白名单命中/未命中/白名单为空三种分支）
