# 错误处理规范

## HTTP 状态码使用规则

HTTP API 使用标准状态码：

| HTTP 状态码 | 使用场景 | 示例 |
|-------------|----------|------|
| 400 BadRequest | 请求参数验证失败 | ID 格式无效、必填字段为空 |
| 401 Unauthorized | 认证失败 | Token 无效或过期 |
| 403 Forbidden | 权限不足 | 越权访问 |
| 404 NotFound | 请求的资源不存在 | 学生不存在、错题不存在 |
| 409 Conflict | 业务前置条件不满足 | 重复提交、状态冲突 |
| 429 TooManyRequests | 资源限制 | 限流、配额耗尽 |
| 500 InternalServerError | 服务内部错误 | 数据库异常、未预期的错误 |
| 503 ServiceUnavailable | 服务不可用 | 依赖服务宕机 |

## 错误信息规范

1. HTTP 错误信息应简洁明确，不包含技术细节
2. 同一类错误在各端点中使用相同的措辞

## 全局异常中间件 (ExceptionHandlingMiddleware)

HTTP 路径使用 `ExceptionHandlingMiddleware` 统一捕获未处理异常，将异常映射为 HTTP 状态码和固定的脱敏 JSON 错误响应（不回显原始异常消息）。中间件在 `Program.cs` 中注册，作用于所有 HTTP 控制器（`AuthController` / `AdminController` / `GatewayController` / `ProfileController`）。

### HTTP 异常处理策略

| 异常类型 | HTTP 状态码 | 响应消息 |
|----------|------------|---------|
| `ArgumentException` | 400 BadRequest | "The request could not be processed." |
| `InvalidOperationException` | 409 Conflict | "The request could not be processed." |
| 其他异常 | 500 Internal Server Error | "An internal error occurred." |

> 中间件不返回原始异常消息（`ex.Message`），只返回上表中固定的脱敏消息，避免泄漏内部实现细节。原始异常信息通过结构化日志记录，供运维排查。

## 参数验证

参数验证应在 HTTP 端点入口处进行，尽早返回错误。

## 日志规范

- 使用结构化日志占位符，不要使用字符串插值
- 异常对象必须传入：使用 `LogError(ex, ...)` 而非 `LogError(ex.Message, ...)`
- 预期内的 NotFound 使用 Warning 级别
- 不记录密码、Token、验证码、AppSecret 等机密信息

### 敏感字段脱敏

写入日志（含 Loki）前，必须对以下字段脱敏。日志最终会进入 Loki 仪表盘，明文敏感信息会违反合规要求：

| 字段类型 | 脱敏规则 | 示例 |
|----------|---------|------|
| 手机号 | 保留前 3 位 + 后 4 位，中间用 `****` 替换；长度不足 7 位时全部替换为 `****` | `138****1234` |
| 微信 OpenId | 保留前 4 + 后 4 位，中间用 `****` 替换；长度不足 8 位时全部替换为 `****` | `o1Qx****wxyz` |
| 刷新令牌 / Access Token / AppSecret / 验证码 | 完全不记录 | — |

实现位置：`Domain.SensitiveDataMasker` 静态工具类。业务代码中使用 `_logger.LogWarning("... Phone={Phone}", SensitiveDataMasker.MaskPhone(phone))` 形式调用。

> 数据库字段（如 `LoginHistoryEntity.ClientIp`、`AuditLogEntity`）不受此规则约束，仍按业务需要存储原始值；该规则仅约束日志输出。

### 限流事件日志

限流触发拒绝时（HTTP JWKS 端点限流器、.NET 8 内置速率限制），必须输出 Warning 级别日志，包含客户端 IP 与命中限流策略，便于在 Loki 上检索攻击或异常调用模式。日志结构化字段：

| 字段 | JWKS 端点 |
|------|----------|
| ClientIp | ✓ |
| PermitLimit | 固定 60 |
| WindowSeconds | 固定 60s |

### CorrelationId 流转

HTTP 路径由 `CorrelationIdMiddleware`（ASP.NET Core 中间件）从请求头 `x-correlation-id` 读取或新建，写入 `HttpContext.Items` 并通过 `ILogger.BeginScope` 注入日志上下文；响应头回写 `x-correlation-id` 便于调用方关联。

HTTP 控制器（`AuthController` / `AdminController` / `GatewayController` / `ProfileController`）必须在该中间件作用范围内。

中间件管道位置（`Program.cs` 中注册顺序）：

```
UseSwagger / UseSwaggerUI (仅 Development)
  → UseMiddleware<CorrelationIdMiddleware>()           ← 必须在 CORS / Auth 之前
  → UseMiddleware<ExceptionHandlingMiddleware>()       ← 新增，统一捕获未处理异常
  → UseCors("AdminWeb")
  → UseAuthentication()
  → 敏感头脱敏中间件（匿名）                            ← 脱敏 Authorization 等敏感请求头
  → UseAuthorization()
  → UseRateLimiter()                                    ← 新增，.NET 8 内置限流
  → MapHealthChecks("/health")
  → JWKS 限流中间件（匿名）                              ← JWKS 端点专属限流
  → MapControllers
```

`CorrelationIdMiddleware` 必须在 CORS 与认证之前注册，确保所有下游中间件（含 CORS 预检、认证失败响应）都在 CorrelationId scope 内。
