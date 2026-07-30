# 刷新令牌吊销 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：当前无 RevokeRefreshToken 专项测试

## 单元测试 — Given-When-Then 格式

### UT-01 空令牌

- **Given** RevokeRequest 中 refresh_token 为空
- **When** 调用 RevokeRefreshToken
- **Then** 返回 success=false

### UT-02 吊销成功

- **Given** 数据库中存在有效的 refresh_token
- **When** 调用 RevokeRefreshToken
- **Then** 令牌 IsRevoked=true，返回 success=true

### UT-03 令牌不存在

- **Given** 数据库中不存在该 refresh_token
- **When** 调用 RevokeRefreshToken
- **Then** 返回 success=false

## 遗漏的测试场景

- 当前无 RevokeRefreshToken 的单元测试 [待补充]
