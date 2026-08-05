# refresh_tokens (刷新令牌表)

刷新令牌表，存储随机字符串（非 JWT），支持撤销和过期清理。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| account_id | UUID | NOT NULL | - | 关联的账户 ID |
| token_value | VARCHAR(256) | NOT NULL, UNIQUE | - | 令牌值（Base64 随机字符串，非 JWT） |
| expires_at | TIMESTAMPTZ | NOT NULL | - | 令牌过期时间 |
| created_at | TIMESTAMPTZ | NOT NULL | - | 令牌创建时间 |
| is_revoked | BOOLEAN | NOT NULL | false | 是否已撤销 |
| app_id | VARCHAR(100) | NULL | - | 关联的应用 ID |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_refresh_tokens_token_value | token_value | UNIQUE | 令牌值唯一索引 |

## 外键关系

- `account_id` → [accounts](./accounts.md).id
- `app_id` → [app_registrations](./app_registrations.md).app_id（逻辑引用，无外键约束）

## 特殊说明

- 令牌值由 `RandomNumberGenerator.GetBytes(64)` 生成后 Base64 编码
- 刷新令牌默认有效期 7 天（可通过 `RefreshToken:ExpirationDays` 配置）
- 使用 refresh_token grant_type 刷新时，旧令牌会被撤销并生成新令牌
- `CleanupWorker` 定期清理过期和已撤销的令牌
- `app_id` 字段通过迁移 `AddAppIdToRefreshToken` 添加，记录令牌发行时的应用 ID（用于审计，不参与校验）。refresh_token 换票不限制应用边界：只要请求方提供有效的 AppId/AppSecret 网关凭据，即可换票。这支持跨应用 SSO 场景（如 A 应用签发的 refresh token 可由 B 应用换票）
