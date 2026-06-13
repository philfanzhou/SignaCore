# 刷新令牌吊销 — 约定与规范 (CONVENTIONS)

## 命名约定

- gRPC 方法名：RevokeRefreshToken
- 请求消息：RevokeRefreshTokenRequest
- 响应消息：BoolResponse

## 日志和安全要求

- 吊销操作无额外日志（由 gRPC 拦截器记录）
- 不区分"不存在"和"已吊销"，防止令牌枚举攻击

## 错误消息格式约定

| 场景 | 消息文本 |
|------|----------|
| 令牌为空 | 无消息（BoolResponse.Success = false） |
| 令牌不存在 | 无消息（BoolResponse.Success = false） |
| 吊销成功 | 无消息（BoolResponse.Success = true） |
