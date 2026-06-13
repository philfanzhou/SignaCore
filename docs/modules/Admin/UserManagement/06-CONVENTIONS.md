# 用户管理 — 约定与规范 (CONVENTIONS)

## 命名约定

- API 路由：`/api/admin/users`、`/api/admin/session/*`
- 请求模型：`Admin{Action}Request`
- 响应模型：`Admin{Entity}Response`

## 日志和安全要求

- 用户创建：LogInformation，记录 UserId、Username
- 管理员登录失败：通过 AuditService 记录
- 管理员登录成功：通过 AuditService 记录
- 启用/禁用用户：通过 AuditService 记录（含 before/after snapshot）

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| 用户名密码为空 | "Username and password cannot be empty." |
| 用户名已存在 | "Username already exists." |
| 手机号已注册 | "Phone number already registered." |
| 用户不存在 | "User not found." |
| 非管理员 | "This account is not authorized for admin access." |
| 密码不符合策略 | 密码策略错误消息 |
