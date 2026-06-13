# 数据库文档

> 本目录是 QuantumZhou.Identity 数据库结构的唯一事实源。模块文档只引用，不重复抄整表定义。

## 表清单

| 表名 | 说明 | 详细文档 |
|------|------|----------|
| accounts | 用户账户主表 | [accounts.md](./tables/accounts.md) |
| password_credentials | 用户名密码凭证表 | [password_credentials.md](./tables/password_credentials.md) |
| user_logins | 外部登录绑定表 | [user_logins.md](./tables/user_logins.md) |
| refresh_tokens | 刷新令牌表 | [refresh_tokens.md](./tables/refresh_tokens.md) |
| app_registrations | 业务系统注册表 | [app_registrations.md](./tables/app_registrations.md) |
| security_keys | RSA 密钥对表 | [security_keys.md](./tables/security_keys.md) |
| otps | 一次性密码记录表 | [otps.md](./tables/otps.md) |
| login_attempts | 登录尝试跟踪表 | [login_attempts.md](./tables/login_attempts.md) |
| login_histories | 登录历史记录表 | [login_histories.md](./tables/login_histories.md) |
| audit_logs | 审计日志表 | [audit_logs.md](./tables/audit_logs.md) |

## 实体关系概述

- `accounts` 是核心实体，被 `password_credentials`、`user_logins`、`refresh_tokens` 引用
- `app_registrations` 独立存在，`refresh_tokens` 通过 `app_id` 逻辑引用
- `security_keys` 独立存在，用于 JWT 签名
- `otps`、`login_attempts` 是临时数据表，有自动清理机制
- `login_histories`、`audit_logs` 是审计数据表，有保留期限制

详细关系图见 [relations.md](./relations.md)

## 迁移历史

| 迁移 ID | 说明 | 详细文档 |
|---------|------|----------|
| 20260502023354 | InitialCreate - 初始建表 | [migrations.md](./migrations.md) |
| 20260502033006 | AddLoginHistoryAndAuditLog - 添加登录历史和审计日志表 | [migrations.md](./migrations.md) |
| 20260502155149 | FixTimestampColumnTypes - 修复时间戳列类型 | [migrations.md](./migrations.md) |
| 20260504150448 | AddAppIdToRefreshToken - 刷新令牌添加 AppId | [migrations.md](./migrations.md) |

详细迁移历史见 [migrations.md](./migrations.md)

## 已移除的表

当前无已移除的表。

## 数据库提供者

支持 SQLite（开发环境）和 PostgreSQL（生产环境），通过 `Database:Provider` 配置切换。

- SQLite：使用 `EnsureCreated()` 初始化
- PostgreSQL：使用 EF Core Migrations，支持自动迁移和 schema reconciliation
