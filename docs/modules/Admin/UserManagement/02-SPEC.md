# 用户管理 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为系统管理员，我希望管理用户账户，以便维护系统中的用户信息。

## 功能要求清单

- [ ] FR-01: 管理员登录（POST /api/admin/session/login）
- [ ] FR-02: 获取当前会话（GET /api/admin/session/me）
- [ ] FR-03: 管理员登出（POST /api/admin/session/logout）
- [ ] FR-04: 查询用户列表（GET /api/admin/users）
- [ ] FR-05: 创建密码用户（POST /api/admin/users）
- [ ] FR-06: 创建手机用户（POST /api/admin/users/phone）
- [ ] FR-07: 修改用户备注（PATCH /api/admin/users/{userId}/remark）
- [ ] FR-08: 修改用户昵称（PATCH /api/admin/users/{userId}/nickname）
- [ ] FR-09: 修改用户状态（PATCH /api/admin/users/{userId}/status）
- [ ] FR-10: 查看用户登录历史（GET /api/admin/users/{userId}/login-history）

### AC-FR-10: 查看用户登录历史
- **Given** 用户存在
- **When** GET /api/admin/users/{userId}/login-history?page=1&pageSize=20
- **Then** 返回 200，分页结果，每条记录包含 AuthMethod、EventType、ClientIp、UserAgent、FailureReason、AppId、CreatedAt

## 详细的验收标准

### AC-FR-01: 管理员登录
- **Given** 有效的用户名和密码，且用户名为 `AdminBootstrap:Username`（唯一管理员）
- **When** POST /api/admin/session/login
- **Then** 签发 Cookie，返回 200

- **Given** 有效的用户名和密码，但用户名 ≠ `AdminBootstrap:Username`
- **When** POST /api/admin/session/login
- **Then** 返回 403（bootstrap_admin_required）

- **Given** `AdminBootstrap:Username` 为空，任意有效账号尝试登录
- **When** POST /api/admin/session/login
- **Then** 返回 403（fail-closed）

### AC-FR-02: 获取当前会话
- **Given** 用户已登录（Cookie 有效）
- **When** GET /api/admin/session/me
- **Then** 返回 200，包含 AccountId、Username、IsAuthenticated=true

- **Given** 用户未登录或 Cookie 无效
- **When** GET /api/admin/session/me
- **Then** 返回 200，IsAuthenticated=false，其余字段为空

### AC-FR-03: 管理员登出
- **Given** 用户已登录
- **When** POST /api/admin/session/logout
- **Then** 签出 Cookie（清除 qz_admin_session），记录审计日志（action=admin_logout），返回 200

### AC-FR-04: 查询用户列表
- **Given** 用户已登录为管理员
- **When** GET /api/admin/users?username=xxx&phone=yyy&page=1&pageSize=20
- **Then** 返回 200，支持 username 和 phone 模糊搜索，分页（默认 pageSize=20，最大 100），每条记录包含 UserId、Username、Phone、IsActive、Remark、Nickname、CreatedAt、DisplayName

### AC-FR-05: 创建密码用户
- **Given** 用户名和密码不为空，密码符合策略，用户名不重复
- **When** POST /api/admin/users
- **Then** 创建 Account + PasswordCredential，返回 200

### AC-FR-06: 创建手机用户
- **Given** 手机号不为空且未注册
- **When** POST /api/admin/users/phone
- **Then** 创建 Account + UserLogin，返回 200

### AC-FR-07: 修改用户备注
- **Given** 用户存在
- **When** PATCH /api/admin/users/{userId}/remark { remark: "xxx" }
- **Then** 更新 Remark 字段，返回 200

- **Given** 用户不存在
- **When** PATCH /api/admin/users/{userId}/remark
- **Then** 返回 404

### AC-FR-08: 修改用户昵称
- **Given** 用户存在
- **When** PATCH /api/admin/users/{userId}/nickname { nickname: "xxx" }
- **Then** 更新 Nickname 字段，返回 200；若 nickname 为空字符串则清除昵称

- **Given** 用户不存在
- **When** PATCH /api/admin/users/{userId}/nickname
- **Then** 返回 404

### AC-FR-09: 修改用户状态
- **Given** 用户存在
- **When** PATCH /api/admin/users/{userId}/status { isActive: false }
- **Then** 更新 IsActive，记录审计日志

## 非功能需求

| 类别 | 需求 |
|------|------|
| 安全 | 所有操作需要 AdminSession 授权 |
| 安全 | 创建用户密码必须符合密码策略 |
| 审计 | 创建、启用/禁用操作记录审计日志 |
| 认证 | 管理员认证使用 Cookie（qz_admin_session），滑动过期 12 小时；勾选 RememberMe 时过期 7 天 |
| 认证 | Cookie 中需包含 admin_access 声明（claim），用于鉴权中间件校验 |
| 安全 | Cookie 属性：HttpOnly、SameSite=Lax、SecurePolicy=SameAsRequest |
| CORS | 管理端 CORS 配置来源于 AdminWeb:AllowedOrigins，仅允许配置的前端域名访问 |

## 测试策略

- [当前无测试覆盖]
