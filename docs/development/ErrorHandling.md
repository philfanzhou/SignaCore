# 错误处理规范

## gRPC 状态码使用规则

gRPC 服务实现中必须使用标准的状态码，不得自定义状态码：

| StatusCode | 使用场景 | 示例 |
|------------|----------|------|
| `InvalidArgument` | 请求参数验证失败 | ID 格式无效、必填字段为空 |
| `NotFound` | 请求的资源不存在 | 学生不存在、错题不存在 |
| `AlreadyExists` | 资源已存在（创建时冲突） | 重复提交 |
| `FailedPrecondition` | 业务前置条件不满足 | 审核非待审核状态的错题 |
| `PermissionDenied` | 权限不足 | 越权访问 |
| `Unauthenticated` | 认证失败 | Token 无效或过期 |
| `ResourceExhausted` | 资源限制 | 限流、配额耗尽 |
| `Internal` | 服务内部错误 | 数据库异常、未预期的错误 |
| `Unavailable` | 服务不可用 | 依赖服务宕机 |

## 错误信息规范

1. gRPC 错误信息使用中文，因为调用方（REST API 控制器）需要将信息展示给终端用户
2. 错误信息应简洁明确，不包含技术细节
3. 同一类错误在各服务中使用相同的措辞

## 全局异常拦截器

所有 gRPC 服务必须注册全局异常拦截器：

- `RpcException` 直接重新抛出，不做包装
- 领域异常映射为 `InvalidArgument` 或 `FailedPrecondition`
- 其他未捕获异常统一返回 `Internal`，错误信息脱敏

## 参数验证

参数验证应在 gRPC 服务方法入口处进行，尽早返回错误。

## 日志规范

- 使用结构化日志占位符，不要使用字符串插值
- 异常对象必须传入：使用 `LogError(ex, ...)` 而非 `LogError(ex.Message, ...)`
- RpcException 应记录状态码和详情
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

所有限流拦截器（gRPC `RateLimitingInterceptor`、HTTP JWKS 端点限流器）触发拒绝时，必须输出 Warning 级别日志，包含客户端 IP 与命中限流策略，便于在 Loki 上检索攻击或异常调用模式。日志结构化字段：

| 字段 | gRPC 拦截器 | JWKS 端点 |
|------|-----------|----------|
| ClientIp | ✓ | ✓ |
| Method | ✓（gRPC 方法名） | — |
| PermitLimit | ✓ | 固定 60 |
| WindowSeconds | ✓ | 固定 60s |

### CorrelationId 流转

CorrelationId 同时适用于 gRPC 与 HTTP 路径：

- gRPC 路径：由 `CorrelationIdInterceptor` 从请求头 `x-correlation-id` 读取或新建，并通过 `ILogger.BeginScope` 注入日志上下文。
- HTTP 路径：由 `CorrelationIdMiddleware`（ASP.NET Core 中间件）从同一请求头读取或新建，写入 `HttpContext.Items` 并通过 `BeginScope` 注入日志上下文；响应头回写 `x-correlation-id` 便于调用方关联。

HTTP 控制器（`AdminController` / `GatewayController` / `ProfileController`）必须在该中间件作用范围内。

中间件管道位置（`Program.cs` 中注册顺序）：

```
UseSwagger (仅 Development)
  → UseMiddleware<CorrelationIdMiddleware>()   ← 必须在 CORS / Auth 之前
  → UseCors("AdminWeb")
  → UseAuthentication()
  → UseAuthorization()
  → JWKS 限流中间件
  → MapControllers / MapGrpcService
```

`CorrelationIdMiddleware` 必须在 CORS 与认证之前注册，确保所有下游中间件（含 CORS 预检、认证失败响应）都在 CorrelationId scope 内。gRPC 请求（`Content-Type: application/grpc`）由中间件自动跳过，避免与 `CorrelationIdInterceptor` 重复生成 ID。
