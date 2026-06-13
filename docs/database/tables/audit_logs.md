# audit_logs (审计日志表)

审计日志表，记录管理操作和关键安全事件的详细信息。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| action | VARCHAR(100) | NOT NULL | - | 操作类型（如 account_created/account_enabled/admin_logout） |
| target_type | VARCHAR(100) | NOT NULL | - | 目标类型（如 Account/AppRegistration/Session/RefreshToken） |
| target_id | VARCHAR(64) | NOT NULL | - | 目标 ID |
| actor_id | UUID | NULL | - | 操作者账户 ID |
| actor_name | VARCHAR(100) | NULL | - | 操作者名称 |
| before_snapshot | VARCHAR(4096) | NULL | - | 操作前快照（JSON） |
| after_snapshot | VARCHAR(4096) | NULL | - | 操作后快照（JSON） |
| description | VARCHAR(1000) | NULL | - | 操作描述 |
| client_ip | VARCHAR(64) | NULL | - | 客户端 IP |
| correlation_id | VARCHAR(64) | NULL | - | 关联请求 ID |
| created_at | TIMESTAMPTZ | NOT NULL | - | 记录创建时间 |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_audit_logs_target | (target_type, target_id, created_at) | NON-UNIQUE | 按目标查询 |
| IX_audit_logs_actor | (actor_id, created_at) | NON-UNIQUE | 按操作者查询 |
| IX_audit_logs_action | (action, created_at) | NON-UNIQUE | 按操作类型查询 |
| IX_audit_logs_created_at | created_at | NON-UNIQUE | 按时间查询/清理 |

## 特殊说明

- 通过迁移 `AddLoginHistoryAndAuditLog` 添加
- 记录保留期默认 365 天（`IdentityConstants.AuditLogRetentionDays`）
- `CleanupWorker` 定期清理超过保留期的记录
- `before_snapshot` 和 `after_snapshot` 使用 camelCase JSON 序列化
- `AuditService.RecordActionAsync` 写入此表，写入失败仅记录日志不抛异常
- 已知 action 值：account_created、account_enabled、account_disabled、admin_logout、app_deleted、app_secret_reset、refresh_token_revoked
