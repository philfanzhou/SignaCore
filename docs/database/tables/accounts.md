# accounts (用户账户主表)

用户账户主表，仅包含通用身份属性。凭证信息存储在 `password_credentials`、`user_logins` 等单独的表中。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| is_active | BOOLEAN | NOT NULL | true | 账户是否活跃（非活跃账户无法登录） |
| created_at | TIMESTAMPTZ | NOT NULL | - | 账户创建时间 |
| remark | VARCHAR(500) | NULL | - | 管理员备注，用于标识账户用途或所有者 |
| remark_normalized | VARCHAR(500) | NULL | - | 备注的 FormC + invariant uppercase 搜索值 |
| nickname | VARCHAR(100) | NULL | - | 用户自定义显示名/昵称 |
| nickname_normalized | VARCHAR(100) | NULL | - | 昵称的 FormC + invariant uppercase 搜索值 |
| last_login_at | TIMESTAMPTZ | NULL | - | 最后登录时间 |
| last_login_ip | VARCHAR(64) | NULL | - | 最后登录 IP |
| last_login_method | VARCHAR(50) | NULL | - | 最后登录方式（Password/Sms/WeChat/RefreshToken） |
| total_login_count | INTEGER | NOT NULL | 0 | 累计登录次数 |

## 索引

无额外索引（主键索引除外）。

## 外键关系

被以下表引用：
- [password_credentials](./password_credentials.md) → account_id
- [user_logins](./user_logins.md) → account_id
- [refresh_tokens](./refresh_tokens.md) → account_id

## 特殊说明

- `nickname` 字段由 `InitialCreate` 迁移创建（曾有一段启动时补列的兼容逻辑，已确认为死代码并删除，见 [migrations.md](../migrations.md)）
- 昵称和备注搜索使用规范化列，不依赖数据库默认 collation
- 登录统计字段（`last_login_at`、`last_login_ip`、`last_login_method`、`total_login_count`）由 `AccountLoginInfoService.UpdateLoginInfoAsync` 更新
