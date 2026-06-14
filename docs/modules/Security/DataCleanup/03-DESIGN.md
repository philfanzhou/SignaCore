# 过期数据自动清理 — 设计说明 (DESIGN)

## 文件结构

```
backend/Domain/CleanupWorker.cs
```

## 关键接口签名

```csharp
public class CleanupWorker : BackgroundService {
    protected override async Task ExecuteAsync(CancellationToken stoppingToken);
}
```

## 数据保留策略

| 数据类型 | 保留期 | 清理方法 | 执行方式 |
|----------|--------|----------|----------|
| RefreshToken | 过期后 | RemoveExpiredAndRevokedAsync | ExecuteDeleteAsync（数据库端直接删除） |
| AppRegistration | 过期后 | DeactivateExpiredCallbacksAsync | ExecuteUpdateAsync（数据库端直接更新） |
| SecurityKey | 过期且非活跃 | RemoveExpiredInactiveAsync | ExecuteDeleteAsync（数据库端直接删除） |
| LoginAttempt | >1 天 | RemoveExpiredAsync | ExecuteDeleteAsync（数据库端直接删除） |
| LoginHistory | >90 天 | RemoveOlderThanAsync | ExecuteDeleteAsync（数据库端直接删除） |
| AuditLog | >365 天 | RemoveOlderThanAsync | ExecuteDeleteAsync（数据库端直接删除） |

## 数据流/调用链

```
CleanupWorker.ExecuteAsync()
    │
    ▼ while (!stoppingToken.IsCancellationRequested)
    │
    ├── CreateScope()
    │
    ├── 1. RemoveExpiredAndRevokedAsync (刷新令牌)
    │      删除已过期或已撤销的 RefreshToken
    │
    ├── 2. DeactivateExpiredCallbacksAsync (应用注册)
    │      将过期的 AppRegistration 标记为不活跃
    │
    ├── 3. RemoveExpiredInactiveAsync (安全密钥)
    │      删除已过期且非活跃的 SecurityKey
    │
    ├── 4. RemoveExpiredAsync (登录尝试)
    │      cutoff = now.AddDays(-1)
    │      删除 1 天前的 LoginAttempt
    │
    ├── 5. RemoveOlderThanAsync (登录历史)
    │      cutoff = now.AddDays(-90)
    │      删除 90 天前的 LoginHistory
    │
    ├── 6. RemoveOlderThanAsync (审计日志)
    │      cutoff = now.AddDays(-365)
    │      删除 365 天前的 AuditLog
    │
    └── 7. NeedsKeyRotationAsync → RotateKeyAsync (密钥轮换)
           检查是否需要轮换，如需要则执行轮换
    │
    ▼ Task.Delay(CleanupIntervalHours)
```

## 关键设计决策

| 决策 | 说明 |
|------|------|
| 使用 Scoped 服务 | 每次清理周期通过 `CreateScope()` 创建新的作用域，避免长生命周期的 DbContext 问题 |
| While 循环 + Delay | 清理在 `while` 循环中执行，每次循环后通过 `Task.Delay` 等待下一个周期 |
| 清理失败容错 | 单个清理步骤失败仅记录错误日志，不中断整个清理流程，后续步骤继续执行 |
| 数据库端执行删除/更新 | 使用 `ExecuteDeleteAsync`/`ExecuteUpdateAsync` 替代 `ToListAsync`+内存 `RemoveRange`，避免全表加载到内存，提升性能和减少内存占用 |
