# 回调注册 — 约定与规范 (CONVENTIONS)

## 命名约定

- HTTP 端点方法名：`RegisterCallback`（`POST /api/auth/callback/register`）
- 请求 DTO：`RegisterCallbackRequest`
- 响应 DTO：`RegisterCallbackResponse`

## 日志和安全要求

- AppSecret 不匹配：LogWarning，记录 AppId
- 注册成功：无额外日志（由 ASP.NET Core 请求日志中间件记录）

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| AppId/AppSecret 为空 | "AppId and AppSecret are required" |
| AppId 未注册 | "AppId not registered" |
| AppSecret 不匹配 | "AppSecret mismatch" |
| 注册成功 | "Registered successfully" |
