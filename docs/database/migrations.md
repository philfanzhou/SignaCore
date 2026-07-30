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

### 20260730134106_AddNormalizedIdentityValues

PostgreSQL 扩展阶段：增加用户名、AppId、ProviderName、昵称和备注的规范化列，暂时保持可空。

### 20260730134156_EnforceNormalizedIdentityValues

PostgreSQL 收缩阶段：启动器使用 `.NET Normalize(FormC) + ToUpperInvariant()` 完成碰撞检测和数据回填后，将关键规范化列设为非空，并把唯一索引切换到规范化列。

### 20260730135237_EnforceSingleOtpPerPhone

将 `otps.phone` 索引收紧为唯一索引，为 OTP 的条件删除和原子失败计数提供单行语义。

## Provider 迁移链

| Provider | 迁移程序集 | 说明 |
|----------|------------|------|
| PostgreSQL | `QuantumZhou.Identity.Database` | 保留全部既有迁移和 `__EFMigrationsHistory` |
| MySQL / MariaDB | `QuantumZhou.Identity.Database.Migrations.MySql` | 共用迁移源码，分别运行契约测试 |
| SQLite | `QuantumZhou.Identity.Database.Migrations.Sqlite` | 使用本地文件数据库和 64 位 Unix 微秒时间 |

## PostgreSQL Schema Reconciliation

在 `Program.cs` 中，启动时对 PostgreSQL 数据库执行 schema reconciliation：
- 检查 `accounts.nickname` 列是否存在，不存在则通过 `ALTER TABLE` 添加
- 如果数据库有表但无迁移历史，自动 stamp 初始迁移

## 注意事项

- Identity 服务启动时无条件执行 EF Core 迁移和 `DatabaseInitializer` 种子逻辑。
- PostgreSQL 通过 advisory lock、MySQL/MariaDB 通过 `GET_LOCK` 串行执行多实例迁移；迁移失败时实例不会进入 Ready。
- SQLite 只允许单实例和实例本地磁盘。
