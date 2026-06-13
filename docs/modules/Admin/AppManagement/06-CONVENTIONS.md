# 应用注册管理 — 约定与规范 (CONVENTIONS)

## 命名约定

- API 路由：`/api/admin/apps`、`/api/admin/tokens/revoke`、`/api/admin/audit-logs`

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| 应用名称为空 | "App name cannot be empty." |
| 应用不存在 | "App not found." |
| 刷新令牌为空 | "Refresh token cannot be empty." |
| 刷新令牌不存在 | "Refresh token not found." |
