# 网关用户查询 — 测试计划 (TESTS)

测试工具：xUnit + Moq + EF Core InMemory
现有测试文件：
- `backend/Tests/unit/Domain/Services/GatewayValidationServiceTests.cs`（网关凭证校验）
- `backend/Tests/unit/Domain/Services/UserQueryServiceTests.cs`（查询与投影唯一实现：搜索过滤/分页/HasPassword/DisplayName 兜底链/批量保序/无效 GUID 过滤/去重）
- `backend/Tests/unit/Host/Controllers/GatewayControllerTests.cs`（端点：401 凭证分支/过滤/分页规范化/批量保序，经真实 UserQueryService + InMemory）

## 单元测试

### UT-01 GatewayValidationService 有效凭证

- **Given** 有效的 AppId 和 AppSecret
- **When** 调用 ValidateAsync
- **Then** 返回 IsSuccess=true

### UT-02 GatewayValidationService 无效凭证

- **Given** 无效的 AppId 或 AppSecret
- **When** 调用 ValidateAsync
- **Then** 返回 IsSuccess=false

### UT-03: 按用户名搜索返回匹配用户

- **Given** 有效的网关凭证，数据库中存在 Username 包含 "zhang" 的用户
- **When** GET /api/gateway/users/search?username=zhang
- **Then** 返回 200 OK，Items 中包含 Username 包含 "zhang" 的用户，Total 正确

### UT-04: 按手机号搜索返回匹配用户

- **Given** 有效的网关凭证，数据库中存在手机号包含 "138" 的用户
- **When** GET /api/gateway/users/search?phone=138
- **Then** 返回 200 OK，Items 中包含 Phone 包含 "138" 的用户

### UT-05: 批量查询有效 ID

- **Given** 有效的网关凭证，请求体 userIds = ["valid-id-1", "valid-id-2"]
- **When** POST /api/gateway/users/batch
- **Then** 返回 200 OK，结果包含两个用户信息，顺序与请求一致

### UT-06: 批量查询过滤无效 GUID

- **Given** 有效的网关凭证，请求体 userIds = ["valid-guid", "not-a-guid", "another-valid-guid"]
- **When** POST /api/gateway/users/batch
- **Then** 返回 200 OK，"not-a-guid" 被过滤掉，仅查询有效 GUID 对应的用户

### UT-07: 缺少网关凭证返回 401

- **Given** 请求未携带 X-Admin-AppId 或 X-Admin-AppSecret 请求头
- **When** GET /api/gateway/users/search 或 POST /api/gateway/users/batch
- **Then** 返回 401 Unauthorized，AdminApiErrorResponse.Message = "Missing gateway credentials."

## 遗漏的测试场景

- 搜索同时提供 username 和 phone 时的 AND 逻辑
- 搜索无匹配结果返回空列表
- App 已禁用返回 401
- App 已过期返回 401
