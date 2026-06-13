# 审计日志记录 — 约定与规范 (CONVENTIONS)

## 已知 action 值

| action | 说明 |
|--------|------|
| account_created | 创建用户 |
| account_enabled | 启用用户 |
| account_disabled | 禁用用户 |
| admin_logout | 管理员登出 |
| app_deleted | 删除应用 |
| app_secret_reset | 重置应用密钥 |
| refresh_token_revoked | 吊销刷新令牌 |

## 已知 target_type 值

| target_type | 说明 |
|-------------|------|
| Account | 账户操作 |
| AppRegistration | 应用操作 |
| Session | 会话操作 |
| RefreshToken | 令牌操作 |

## 快照格式

before/after snapshot 使用 camelCase JSON 序列化。
