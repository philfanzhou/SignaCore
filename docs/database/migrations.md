# 迁移历史

## 迁移清单

### 20260502023354_InitialCreate

初始建表迁移，创建以下表：
- accounts
- password_credentials
- user_logins
- refresh_tokens
- app_registrations
- security_keys
- otps
- login_attempts

### 20260502033006_AddLoginHistoryAndAuditLog

添加登录历史和审计日志表：
- login_histories
- audit_logs

### 20260502155149_FixTimestampColumnTypes

修复时间戳列类型，将 `DateTime` 列统一为 `TIMESTAMPTZ`（PostgreSQL）类型。

### 20260504150448_AddAppIdToRefreshToken

为 `refresh_tokens` 表添加 `app_id` 列（VARCHAR(100)，可为 NULL），用于验证刷新令牌与请求应用的匹配关系。

## PostgreSQL Schema Reconciliation

在 `Program.cs` 中，启动时对 PostgreSQL 数据库执行 schema reconciliation：
- 检查 `accounts.nickname` 列是否存在，不存在则通过 `ALTER TABLE` 添加
- 如果数据库有表但无迁移历史，自动 stamp 初始迁移

## 注意事项

- PostgreSQL 环境使用 `Database.Migrate()` 应用迁移
- Identity 服务启动时无条件自动执行 EF Core 迁移和 `DatabaseInitializer` 种子逻辑。生产环境无需手动执行迁移命令
