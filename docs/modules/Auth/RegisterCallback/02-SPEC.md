# 回调注册 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为业务系统的开发者，我希望注册权限回调地址，以便用户登录时 Identity 服务能回调获取角色和权限。

## 功能要求清单

- [ ] FR-01: 验证 AppId 和 AppSecret 不为空
- [ ] FR-02: 验证 AppId 已注册
- [ ] FR-03: 验证 AppSecret 匹配（BCrypt）
- [ ] FR-04: 更新 CallbackUrl 和 CallbackExpiresAt
- [ ] FR-05: 支持 TTL = -1 表示永不过期

## 详细的验收标准

### AC-FR-01: 参数验证
- **Given** RegisterCallbackRequest
- **When** AppId 或 AppSecret 为空
- **Then** 返回 success=false, message="AppId and AppSecret are required"

### AC-FR-02: AppId 验证
- **Given** RegisterCallbackRequest
- **When** AppId 未注册
- **Then** 返回 success=false, message="AppId not registered"

### AC-FR-03: AppSecret 验证
- **Given** RegisterCallbackRequest
- **When** AppSecret 不匹配
- **Then** 返回 success=false, message="AppSecret mismatch"

### AC-FR-04: 注册成功
- **Given** 有效的 AppId + AppSecret + CallbackUrl
- **When** TtlSeconds > 0
- **Then** 更新 CallbackUrl 和 CallbackExpiresAt，返回 success=true

### AC-FR-05: 永不过期
- **Given** 有效的 AppId + AppSecret + CallbackUrl
- **When** TtlSeconds = -1
- **Then** CallbackExpiresAt 为 null，返回 success=true, expires_at=0

## 非功能需求

| 类别 | 需求 |
|------|------|
| 安全 | AppSecret 使用 BCrypt.Verify 验证 |
| 安全 | AppSecret 不匹配时记录 Warning 日志 |

## 测试策略

- 单元测试覆盖参数验证、AppId 查找、AppSecret 验证、TTL 处理
- [当前无测试覆盖]
