# login_histories (登录历史记录表)

登录历史记录表，记录每次登录尝试的详细信息，用于安全审计和统计分析。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| account_id | UUID | NULL | - | 关联的账户 ID（登录失败时可能为 NULL） |
| username | VARCHAR(100) | NOT NULL | - | 用户名或标识 |
| auth_method | VARCHAR(50) | NOT NULL | - | 认证方式（Password/Sms/WeChat/RefreshToken/admin_login） |
| event_type | VARCHAR(50) | NOT NULL | - | 事件类型（login_success/login_failure） |
| client_ip | VARCHAR(64) | NULL | - | 客户端 IP |
| user_agent | VARCHAR(512) | NULL | - | 用户代理字符串 |
| failure_reason | VARCHAR(500) | NULL | - | 失败原因 |
| app_id | VARCHAR(100) | NULL | - | 关联的应用 ID |
| correlation_id | VARCHAR(64) | NULL | - | 关联请求 ID |
| created_at | TIMESTAMPTZ | NOT NULL | - | 记录创建时间 |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_login_histories_account_id | account_id | NON-UNIQUE | 按账户查询历史 |
| IX_login_histories_created_at | created_at | NON-UNIQUE | 按时间查询/清理 |
| IX_login_histories_client_ip | client_ip | NON-UNIQUE | 按 IP 查询 |

## 特殊说明

- 通过迁移 `AddLoginHistoryAndAuditLog` 添加
- 记录保留期默认 90 天（`IdentityConstants.LoginHistoryRetentionDays`）
- `CleanupWorker` 定期清理超过保留期的记录
- `AuditService.RecordLoginAsync` 写入此表，写入失败仅记录日志不抛异常
