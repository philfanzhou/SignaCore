# 用户昵称管理 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：当前无专项测试

## 单元测试

### UT-01: 获取个人资料 — 有效 JWT

- **Given** 有效的 JWT Bearer Token（ClaimTypes.NameIdentifier 包含有效 accountId），数据库中存在对应账户
- **When** 调用 `GetProfile`
- **Then** 返回 200 OK，ProfileResponse 包含正确的 UserId、Nickname、IsActive、CreatedAt

### UT-02: 更新昵称成功

- **Given** 有效的 JWT Bearer Token，数据库中存在对应账户，请求体 Nickname = "新昵称"（≤100 字符）
- **When** 调用 `UpdateNickname`
- **Then** 返回 200 OK，OperationResponse.Success = true，数据库中 Nickname 更新为 "新昵称"（Trim 后）

### UT-03: 昵称超过最大长度

- **Given** 有效的 JWT Bearer Token，数据库中存在对应账户，请求体 Nickname 长度 > 100 字符（`IdentityConstants.MaxNicknameLength`）
- **When** 调用 `UpdateNickname`
- **Then** 返回 400 BadRequest，ErrorResponse.Message 包含 "Nickname cannot exceed 100 characters."，数据库中 Nickname 未变更

### UT-04: 清除昵称（设为 null/空字符串）

- **Given** 有效的 JWT Bearer Token，数据库中存在对应账户且当前有昵称，请求体 Nickname = null 或 "" 或 "   "
- **When** 调用 `UpdateNickname`
- **Then** 返回 200 OK，数据库中 Nickname 被设为 null

### UT-05: 未认证请求（无 JWT）

- **Given** 请求未携带 JWT Bearer Token
- **When** 调用 `GetProfile` 或 `UpdateNickname`
- **Then** 返回 401 Unauthorized（由 `[Authorize(Policy = "UserProfile")]` 中间件拦截）

## 遗漏的测试场景

- JWT 中 NameIdentifier 为无效 Guid 时的 401 响应
- JWT 中 NameIdentifier 对应的账户不存在时的 401 响应
- 昵称恰好为 100 字符时的边界测试（应成功）
- 昵称为 101 字符时的边界测试（应失败）
- 昵称包含前后空白字符时的 Trim 行为验证
- `unitOfWork.SaveChangesAsync()` 失败时的异常处理
- 并发更新昵称的竞态条件
