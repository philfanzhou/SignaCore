# 网关用户查询 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：test/Domain/Services/GatewayValidationServiceTests.cs

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

- GatewayController 端到端测试（搜索、批量查询）
- 搜索结果分页边界测试（page=0 应规范化为 1，pageSize=0 应规范化为 20）
- 搜索结果分页上限测试（pageSize > 100 应被截断为 100）
- 批量查询空列表返回空数组
- 批量查询结果保持请求顺序（包含不存在的 ID）
- 批量查询去重测试（重复 ID 只查询一次）
- 无效 AppSecret 返回 401（GatewayValidationService 验证失败）
- App 已禁用返回 401
- App 已过期返回 401
- 搜索同时提供 username 和 phone 时的 AND 逻辑
- 搜索无匹配结果返回空列表
- ProjectUsersAsync 中 DisplayName 计算逻辑的各分支测试
