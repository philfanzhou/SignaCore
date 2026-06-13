# otps (一次性密码记录表)

一次性密码记录，用于短信登录验证。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| phone | VARCHAR(20) | NOT NULL | - | 手机号 |
| code | VARCHAR(10) | NOT NULL | - | 验证码 |
| expires_at | TIMESTAMPTZ | NOT NULL | - | 验证码过期时间 |
| attempts | INTEGER | NOT NULL | 0 | 验证尝试次数 |
| lockout_until | TIMESTAMPTZ | NOT NULL | - | 锁定过期时间 |
| created_at | TIMESTAMPTZ | NOT NULL | - | 记录创建时间 |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_otps_phone | phone | NON-UNIQUE | 按手机号查询 |

## 特殊说明

- 验证码默认有效期 300 秒（5 分钟），可通过 `Sms:OtpTtlSeconds` 配置
- 最大验证尝试次数默认 5 次，可通过 `Sms:MaxAttempts` 配置
- 超过最大尝试次数后锁定，锁定时间默认 600 秒（10 分钟），可通过 `Sms:LockoutSeconds` 配置
- 验证成功后记录立即删除
- 此表仅在 `DbOtpService` 中使用；`InMemoryOtpService` 使用内存存储，不写入此表
