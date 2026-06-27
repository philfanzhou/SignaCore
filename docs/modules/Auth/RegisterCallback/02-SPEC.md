# 回调注册 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为业务系统的开发者，我希望注册权限回调地址，以便用户登录时 Identity 服务能回调获取角色和权限。

## 功能要求清单

- [ ] FR-01: 验证 AppId 和 AppSecret 不为空
- [ ] FR-02: 验证 CallbackUrl 格式（如非空），包括 URL 有效性、协议限制、可选的私有 IP 禁用、域名白名单
- [ ] FR-03: 验证 AppId 已注册
- [ ] FR-04: 验证 AppSecret 匹配（BCrypt）
- [ ] FR-05: 更新 CallbackUrl 和 CallbackExpiresAt
- [ ] FR-06: 支持 TTL = -1 表示永不过期

## 详细的验收标准

### AC-FR-01: 参数验证
- **Given** RegisterCallbackRequest
- **When** AppId 或 AppSecret 为空
- **Then** 返回 success=false, message="AppId and AppSecret are required"

### AC-FR-02: CallbackUrl 验证
- **Given** RegisterCallbackRequest 且 CallbackUrl 非空
- **When** CallbackUrl 不是有效的绝对 URL
- **Then** 返回 success=false, message 包含 "Invalid callback URL"

- **Given** RegisterCallbackRequest 且 CallbackUrl 使用 ftp:// 等非 HTTP/HTTPS 协议
- **When** 验证
- **Then** 返回 success=false, message 包含 "HTTP or HTTPS"

- **Given** RegisterCallbackRequest 且 CallbackUrl 解析到私有 IP（如 192.168.x.x）
- **When** 显式配置 AllowPrivateAddresses=false
- **Then** 返回 success=false, message 包含 "private/internal IP address"

- **Given** RegisterCallbackRequest 且 CallbackUrl 域名不在白名单中
- **When** 配置了 AllowedDomains
- **Then** 返回 success=false, message 包含 "not in the allowed domains list"

### AC-FR-03: AppId 验证
- **Given** RegisterCallbackRequest
- **When** AppId 未注册
- **Then** 返回 success=false, message="AppId not registered"

### AC-FR-04: AppSecret 验证
- **Given** RegisterCallbackRequest
- **When** AppSecret 不匹配
- **Then** 返回 success=false, message="AppSecret mismatch"

### AC-FR-05: 注册成功
- **Given** 有效的 AppId + AppSecret + CallbackUrl
- **When** TtlSeconds > 0
- **Then** 更新 CallbackUrl 和 CallbackExpiresAt，返回 success=true

### AC-FR-06: 永不过期
- **Given** 有效的 AppId + AppSecret + CallbackUrl
- **When** TtlSeconds = -1
- **Then** CallbackExpiresAt 为 null，返回 success=true, expires_at=0

## 非功能需求

| 类别 | 需求 |
|------|------|
| 安全 | AppSecret 使用 BCrypt.Verify 验证 |
| 安全 | AppSecret 不匹配时记录 Warning 日志 |
| 安全 | CallbackUrl 验证：仅允许 HTTP/HTTPS 协议、默认允许私有 IP（可显式禁用）、域名白名单 |
| 安全 | CallbackUrl DNS 解析使用异步方法（ValidateAsync），避免阻塞请求线程 |

## 测试策略

- 单元测试覆盖参数验证、AppId 查找、AppSecret 验证、TTL 处理
- 单元测试覆盖 CallbackUrl 验证：无效 URL、非 HTTP 协议、私有 IP、域名白名单
- 单元测试覆盖 CallbackUrlValidator.ValidateAsync 异步方法
- 测试文件：`test/AuthServiceImplTests.cs`、`test/Domain/CallbackUrlValidatorTests.cs`
