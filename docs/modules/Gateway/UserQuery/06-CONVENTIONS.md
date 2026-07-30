# 网关用户查询 — 约定与规范 (CONVENTIONS)

## 命名约定

- API 路由：`/api/gateway/users/*`
- 认证头：`X-Admin-AppId`、`X-Admin-AppSecret`

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| 缺少网关凭证 | "Missing gateway credentials." |
| 网关认证失败 | "Gateway authentication failed." |
