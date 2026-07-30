# 应用注册管理 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：当前无专项测试

## 单元测试 — Given-When-Then 格式

### UT-01 创建应用返回 AppId 和明文 AppSecret

- **Given** 管理员已登录，AppName 不为空
- **When** POST /api/admin/apps { appName: "test-app" }
- **Then** 返回 200，包含 AppId（32 位十六进制）和明文 AppSecret（Base64 编码），数据库中 AppSecretHash 为 BCrypt 哈希

### UT-02 查询应用列表按创建日期排序

- **Given** 数据库中存在多个应用
- **When** GET /api/admin/apps
- **Then** 返回 200，应用列表按 CreatedAt 降序排列，每条包含 AppId/AppName/CallbackUrl/CallbackExpiresAt/IsActive/CreatedAt

### UT-03 更新回调配置（有效 URL）

- **Given** AppId 存在
- **When** PUT /api/admin/apps/{appId}/callback { callbackUrl: "https://example.com/callback", ttlSeconds: 7200 }
- **Then** 返回 200，CallbackUrl 和 CallbackExpiresAt 更新，ExpiresAt=now+7200s

### UT-04 删除应用从数据库移除

- **Given** AppId 存在
- **When** DELETE /api/admin/apps/{appId}
- **Then** 返回 200，数据库中该应用记录被移除，AuditService 记录审计日志

### UT-05 重置密钥返回新明文 AppSecret

- **Given** AppId 存在
- **When** POST /api/admin/apps/{appId}/reset-secret
- **Then** 返回 200，包含新的明文 AppSecret，数据库中 AppSecretHash 更新为新的 BCrypt 哈希，旧密钥失效

### UT-06 吊销刷新令牌记录审计日志

- **Given** 刷新令牌存在
- **When** POST /api/admin/tokens/revoke { token }
- **Then** 令牌被吊销，AuditService 记录审计日志，返回 200

## 遗漏的测试场景

- 当前无 AppManagement 的单元测试 [待补充]
