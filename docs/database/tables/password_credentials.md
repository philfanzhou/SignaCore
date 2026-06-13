# password_credentials (用户名密码凭证表)

用户名/密码凭证表，支持一个账户绑定多个用户名。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| account_id | UUID | NOT NULL | - | 关联的账户 ID |
| username | VARCHAR(100) | NOT NULL, UNIQUE | - | 用户名（唯一） |
| password_hash | VARCHAR(256) | NOT NULL | - | BCrypt 密码哈希 |
| created_at | TIMESTAMPTZ | NOT NULL | - | 凭证创建时间 |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_password_credentials_username | username | UNIQUE | 用户名唯一索引 |
| IX_password_credentials_account_id | account_id | NON-UNIQUE | 按账户查询凭证 |

## 外键关系

- `account_id` → [accounts](./accounts.md).id

## 特殊说明

- 密码使用 BCrypt 哈希存储，WorkFactor 默认 11（可通过 `PasswordHasher:WorkFactor` 配置）
- 密码策略要求：最少 8 字符，包含大写字母、小写字母和数字
