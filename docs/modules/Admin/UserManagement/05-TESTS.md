# 用户管理 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：当前无 AdminController 专项测试

## 单元测试 — Given-When-Then 格式

### UT-01 管理员登录成功

- **Given** 有效的用户名密码，用户名在白名单中
- **When** POST /api/admin/session/login
- **Then** 返回 200，设置 Cookie

### UT-02 管理员登录白名单拒绝

- **Given** 有效的用户名密码，用户名不在白名单中
- **When** POST /api/admin/session/login
- **Then** 返回 403

### UT-03 创建密码用户

- **Given** 用户名不重复，密码符合策略
- **When** POST /api/admin/users
- **Then** 返回 200，创建 Account + PasswordCredential

### UT-04 创建手机用户

- **Given** 手机号未注册
- **When** POST /api/admin/users/phone
- **Then** 返回 200，创建 Account + UserLogin

### UT-05 获取当前会话（有效 Cookie）

- **Given** 用户已登录，Cookie 有效
- **When** GET /api/admin/session/me
- **Then** 返回 200，IsAuthenticated=true，包含 AccountId、Username、AdminUsernamesConfigured

### UT-06 登出记录审计日志

- **Given** 用户已登录
- **When** POST /api/admin/session/logout
- **Then** 签出 Cookie，AuditService 记录 action=admin_logout，返回 200

### UT-07 查询用户列表（用户名过滤）

- **Given** 数据库中存在用户名为 "testuser" 的用户
- **When** GET /api/admin/users?username=test
- **Then** 返回 200，结果中包含用户名含 "test" 的用户，每条记录包含 UserId/Username/Phone/IsActive/Remark/Nickname/CreatedAt/DisplayName

### UT-08 修改备注用户不存在返回 404

- **Given** userId 对应的用户不存在
- **When** PATCH /api/admin/users/{userId}/remark { remark: "test" }
- **Then** 返回 404

### UT-09 修改昵称空字符串清除昵称

- **Given** 用户存在且当前昵称为 "旧昵称"
- **When** PATCH /api/admin/users/{userId}/nickname { nickname: "" }
- **Then** 返回 200，Nickname 字段被清空

### UT-10 禁用用户记录审计日志（含前后快照）

- **Given** 用户存在且 IsActive=true
- **When** PATCH /api/admin/users/{userId}/status { isActive: false }
- **Then** 更新 IsActive=false，AuditService 记录审计日志，包含 before/after 快照（before: IsActive=true, after: IsActive=false）

## 遗漏的测试场景

- 当前无 AdminController 的单元测试 [待补充]
