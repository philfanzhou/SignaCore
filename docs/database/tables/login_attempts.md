# login_attempts (登录尝试跟踪表)

登录尝试跟踪和账户锁定记录，用于密码登录的防暴力破解保护。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| username | VARCHAR(100) | NOT NULL, UNIQUE | - | 用户名 |
| last_attempt_at | TIMESTAMPTZ | NOT NULL | - | 最后一次尝试时间 |
| failed_attempts | INTEGER | NOT NULL | 0 | 连续失败次数 |
| lockout_until | TIMESTAMPTZ | NULL | - | 锁定过期时间（NULL 表示未锁定） |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_login_attempts_username | username | UNIQUE | 用户名唯一索引 |

## 特殊说明

- 最大失败次数默认 5 次（`IdentityConstants.MaxFailedLoginAttempts`）
- 锁定时间默认 15 分钟（`IdentityConstants.LoginLockoutMinutes`）
- 登录成功后，该用户的 `login_attempts` 记录会被删除
- `CleanupWorker` 定期清理超过 1 天的过期记录
