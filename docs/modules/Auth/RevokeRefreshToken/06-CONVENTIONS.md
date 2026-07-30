# 刷新令牌吊销 — 约定与规范 (CONVENTIONS)

## 命名约定

- HTTP 端点方法名：`RevokeRefreshToken`（`POST /api/auth/revoke`）
- 请求 DTO：`RevokeRequest`
- 响应 DTO：`RevokeResponse`

## 日志和安全要求

- 吊销操作无额外日志（由 ASP.NET Core 请求日志中间件记录）
- 不区分"不存在"和"已吊销"，防止令牌枚举攻击

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| 令牌为空 | 无消息（RevokeResponse.Success = false） |
| 令牌不存在 | 无消息（RevokeResponse.Success = false） |
| 吊销成功 | 无消息（RevokeResponse.Success = true） |
