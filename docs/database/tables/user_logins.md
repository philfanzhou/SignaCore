# user_logins (外部登录绑定表)

外部登录绑定表，用于第三方登录方式（如微信、短信）。一个账户可以有多个外部登录绑定。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| account_id | UUID | NOT NULL | - | 关联的账户 ID |
| provider_name | VARCHAR(100) | NOT NULL | - | 提供商名称（如 WeChat、Sms） |
| provider_name_normalized | VARCHAR(100) | NOT NULL | - | FormC + invariant uppercase 提供商名称 |
| provider_user_id | VARCHAR(256) | NOT NULL | - | 提供商用户唯一标识（如微信 OpenId、手机号） |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_user_logins_provider_name_normalized_provider_user_id | (provider_name_normalized, provider_user_id) | UNIQUE | 大小写不敏感提供商名称 + 大小写敏感用户 ID |
| IX_user_logins_account_id | account_id | NON-UNIQUE | 按账户查询绑定 |

## 外键关系

- `account_id` → [accounts](./accounts.md).id

## 特殊说明

- `provider_name` 的已知值：`Sms`（短信登录）、`WeChat`（微信登录）
- `provider_name` 大小写不敏感，`provider_user_id` 保持大小写敏感
- 短信登录时 `provider_user_id` 存储手机号
- 微信登录时 `provider_user_id` 存储 OpenId
