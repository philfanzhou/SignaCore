# 网关用户查询 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为业务系统的后端服务，我希望通过网关 API 查询用户信息，以便在业务流程中获取用户的基本身份信息。

- 业务系统通过 AppId/AppSecret 认证后查询用户信息
- 所有请求必须携带 `X-Admin-AppId` 和 `X-Admin-AppSecret` 请求头
- 查询结果不包含敏感信息（密码哈希等）
- 不提供用户创建/修改能力
- 不提供用户权限信息（由回调机制获取）

## 功能要求清单

- [ ] FR-01: 搜索用户（GET /api/gateway/users/search）
- [ ] FR-02: 批量查询用户（POST /api/gateway/users/batch）

## 详细的验收标准

### AC-FR-01: 搜索用户
- **Given** 有效的 AppId/AppSecret（通过 X-Admin-AppId / X-Admin-AppSecret 请求头），搜索关键词
- **When** GET /api/gateway/users/search?username=xxx
- **Then** 返回匹配的用户列表（分页），包含 UserId、Username、Phone、IsActive、Remark、Nickname、CreatedAt、DisplayName、HasPassword

### AC-FR-01-补充：分页参数
- **Given** 有效的 AppId/AppSecret
- **When** GET /api/gateway/users/search?username=xxx&page=2&pageSize=50
- **Then** 返回第 2 页，每页 50 条记录；pageSize 上限为 100，默认 20；page 默认 1

### AC-FR-01-补充：手机号搜索
- **Given** 有效的 AppId/AppSecret
- **When** GET /api/gateway/users/search?phone=138xxxx
- **Then** 返回手机号包含该关键词的用户列表

### AC-FR-02: 批量查询
- **Given** 有效的 AppId/AppSecret，用户 ID 列表
- **When** POST /api/gateway/users/batch
- **Then** 按请求顺序返回用户信息

### AC-FR-02-补充：空列表
- **Given** 有效的 AppId/AppSecret，userIds 为 null 或空列表
- **When** POST /api/gateway/users/batch
- **Then** 返回空列表 `[]`

### AC-FR-02-补充：无效 GUID 过滤
- **Given** 有效的 AppId/AppSecret，userIds 包含无效 GUID 字符串
- **When** POST /api/gateway/users/batch
- **Then** 无效 GUID 被过滤掉，仅查询有效 GUID 对应的用户

### AC-FR-02-补充：结果保持请求顺序
- **Given** 有效的 AppId/AppSecret，userIds = ["id-A", "id-B", "id-C"]
- **When** POST /api/gateway/users/batch
- **Then** 返回结果按 id-A, id-B, id-C 的顺序排列（不存在的 ID 不出现在结果中）

## 非功能需求

- **NFR-01 安全性**：所有请求必须通过 `X-Admin-AppId` 和 `X-Admin-AppSecret` 请求头提供凭证，由 `GatewayValidationService.ValidateAsync` 验证；缺少凭证返回 401，无效凭证返回 401
- **NFR-02 数据约束**：分页 pageSize 最大值为 100（`Math.Min(normalizedPageSize, 100)`），默认 20；page 默认 1
- **NFR-03 数据脱敏**：查询结果不包含密码哈希等敏感字段，仅返回 UserId、Username、Phone、IsActive、Remark、Nickname、CreatedAt、DisplayName、HasPassword（布尔，标识账户是否持有密码凭据，不含任何凭据内容）
- **NFR-04 凭证验证流程**：AppId 查找注册记录 → 检查 App 是否激活 → 检查是否过期 → BCrypt 验证 AppSecret

## 测试策略

- `UserQueryServiceTests`：查询与投影逻辑（搜索过滤、分页、HasPassword 判据、DisplayName 兜底、批量保序/无效 GUID 过滤/去重）
- `GatewayControllerTests`：端点行为（401 凭证分支、分页规范化、批量保序，注入真实 UserQueryService + EF InMemory）
- `GatewayValidationServiceTests`：AppId/AppSecret 校验
