# app_registrations (业务系统注册表)

业务系统注册表，支持基于动态回调的权限注入。业务系统启动时注册 AppId/AppSecret 和回调地址，Identity 在登录后回调获取用户权限并注入 JWT。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| app_id | VARCHAR(100) | NOT NULL | - | 应用唯一标识原始值 |
| app_id_normalized | VARCHAR(100) | NOT NULL, UNIQUE | - | FormC + invariant uppercase AppId |
| app_secret_hash | VARCHAR(256) | NOT NULL | - | BCrypt 哈希的应用密钥 |
| app_name | VARCHAR(200) | NOT NULL | - | 业务系统显示名称 |
| callback_url | VARCHAR(500) | NULL | - | 回调地址，Identity 登录后回调获取用户权限 |
| is_active | BOOLEAN | NOT NULL | true | 是否活跃 |
| created_at | TIMESTAMPTZ | NOT NULL | - | 注册时间 |
| callback_expires_at | TIMESTAMPTZ | NULL | - | 回调注册过期时间 |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_app_registrations_app_id_normalized | app_id_normalized | UNIQUE | 大小写不敏感应用 ID 唯一索引 |

## 特殊说明

- AppSecret 使用 BCrypt 哈希存储，验证时使用 `BCrypt.Verify`
- AppId 查询和唯一性使用 `app_id_normalized`
- 回调地址支持 TTL 机制：`TtlSeconds = -1` 表示永不过期，否则默认 3600 秒
- `callback_expires_at` 为 NULL 时表示永不过期
- `CleanupWorker` 定期将过期的应用注册标记为不活跃
- 启动时可通过 `data/bootstrap-apps.json` 预置应用注册，AppId 已存在则跳过（幂等）。
  预置内容由部署方提供，Identity 不内置任何具体业务应用（见 [Configuration.md](../../development/Configuration.md) "Bootstrap Apps 配置"）
