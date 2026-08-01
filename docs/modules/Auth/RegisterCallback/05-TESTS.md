# 回调注册 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：当前无 RegisterCallback 专项测试

## 单元测试 — Given-When-Then 格式

### UT-01 参数为空

- **Given** RegisterCallbackRequest 中 AppId 或 AppSecret 为空
- **When** 调用 RegisterCallback
- **Then** 返回 success=false, message="AppId and AppSecret are required"

### UT-02 AppId 未注册

- **Given** AppId 在数据库中不存在
- **When** 调用 RegisterCallback
- **Then** 返回 success=false, message="AppId not registered"

### UT-03 AppSecret 不匹配

- **Given** AppId 存在但 AppSecret 不匹配
- **When** 调用 RegisterCallback
- **Then** 返回 success=false, message="AppSecret mismatch"

### UT-04 注册成功

- **Given** 有效的 AppId + AppSecret + CallbackUrl
- **When** 调用 RegisterCallback
- **Then** 更新 CallbackUrl 和 CallbackExpiresAt，返回 success=true

## 遗漏的测试场景

- 当前无 RegisterCallback 的单元测试 [待补充]
- CallbackUrl 格式验证测试
- TTL = -1 永不过期场景测试
