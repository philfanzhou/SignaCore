# 审计日志记录 — 设计说明 (DESIGN)

## 文件结构

```
backend/Domain/Services/AuditService.cs
backend/Domain/Services/IAuditService.cs
```

## 关键接口签名

```csharp
public interface IAuditService {
    Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
        string? clientIp, string? userAgent, string? failureReason = null,
        string? appId = null, string? correlationId = null);
    Task RecordActionAsync(string action, string targetType, string targetId,
        Guid? actorId, string? actorName, string? description, string? clientIp = null,
        string? correlationId = null, object? before = null, object? after = null);
}
```

## 依赖的数据库表

- [login_histories](../../../database/tables/login_histories.md)
- [audit_logs](../../../database/tables/audit_logs.md)

## 数据流/调用链

### RecordLoginAsync

```
RecordLoginAsync(accountId, username, authMethod, eventType, clientIp, userAgent, ...)
    │
    ▼ try
    ├── 创建 LoginHistory 实体
    │     accountId, username, authMethod, eventType,
    │     clientIp, userAgent, failureReason, appId, correlationId
    │
    ├── _context.LoginHistories.Add(entity)
    │
    └── _context.SaveChangesAsync()
    │
    ▼ catch (Exception)
    └── _logger.LogError(ex, "Failed to record login event")
```

### RecordActionAsync

```
RecordActionAsync(action, targetType, targetId, actorId, actorName, description, ...)
    │
    ▼ try
    ├── 序列化 before/after 快照
    │     JsonSerializer.Serialize(before, CamelCaseNamingPolicy)
    │     JsonSerializer.Serialize(after, CamelCaseNamingPolicy)
    │
    ├── 创建 AuditLog 实体
    │     action, targetType, targetId, actorId, actorName,
    │     description, clientIp, correlationId, beforeSnapshot, afterSnapshot
    │
    ├── _context.AuditLogs.Add(entity)
    │
    └── _context.SaveChangesAsync()
    │
    ▼ catch (Exception)
    └── _logger.LogError(ex, "Failed to record audit action")
```

## 关键设计决策

| 决策 | 说明 |
|------|------|
| try-catch 防护 | AuditService 的 `RecordLoginAsync` 和 `RecordActionAsync` 均使用 try-catch 包裹，确保审计写入失败不会影响业务操作的正常执行 |
| 快照序列化 | before/after 快照使用 `JsonSerializer` 序列化，配置 `CamelCaseNamingPolicy` 确保 JSON 字段名为 camelCase 格式 |
| 独立事务 | 每个审计方法独立调用 `SaveChangesAsync`，每条审计记录是独立的事务，不与业务操作共享 DbContext 事务 |
