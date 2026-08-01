# 网关用户查询 — 设计说明 (DESIGN)

## 文件结构

```
backend/Host/Controllers/GatewayController.cs
backend/Domain/Services/IUserQueryService.cs     (查询接口，Admin/Gateway 共用)
backend/Domain/Services/UserQueryService.cs      (查询与投影唯一实现)
backend/Domain/Services/GatewayValidationService.cs
backend/Domain/Models/UserListItemResponse.cs    (UserListItemResponse 唯一定义)
backend/Domain/Models/PagedResponse.cs           (PagedResponse<T>、PageRequest 分页归一化)
backend/Database/IdentityConstants.cs            (AuthMethodSms)
```

## 关键接口签名和数据结构定义

```csharp
// Domain/Services/IUserQueryService.cs —— Admin/Gateway 两端用户查询的唯一实现
public interface IUserQueryService
{
    Task<(List<UserListItemResponse> Users, int Total)> SearchUsersAsync(
        string? username, string? phone, int page, int pageSize);
    Task<List<UserListItemResponse>> GetUsersByIdsAsync(List<string> userIds);
}

// Domain/Models/AdminModels.cs —— DTO 唯一定义处（原 Host/Models 重复定义已删除，两端统一引用 Domain 版）
public sealed record PagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed record UserListItemResponse(
    string UserId,
    string Username,
    string Phone,
    bool IsActive,
    string Remark,
    string? Nickname,
    long CreatedAt,
    string DisplayName,
    bool HasPassword);
```

> **收敛说明（2026-07-21）**：`AdminController.GetUsers`、`GatewayController.SearchUsers`/`GetUsersByIds` 曾各自内联一份相同的查询+投影逻辑（曾因此漏改 Gateway 一处导致 HasPassword 不一致）。现已收敛为三端统一注入 `IUserQueryService`，Controller 仅负责参数规范化（page/pageSize 钳制）与鉴权。

## 数据流/调用链

### SearchUsers
```
Client ──GET /api/gateway/users/search──▶ GatewayController
  │                                         │
  │  Headers: X-Admin-AppId, X-Admin-AppSecret
  │                                         │  1. ValidateGatewayRequestAsync()
  │                                         │     ├─ 读取 X-Admin-AppId / X-Admin-AppSecret
  │                                         │     ├─ 缺少凭证 → 401
  │                                         │     └─ gatewayValidationService.ValidateAsync()
  │                                         │        └─ 无效 → 401
  │                                         │
  │                                         │  2. 规范化分页参数 (page默认1, pageSize默认20, 上限100)
  │                                         │  3. userQueryService.SearchUsersAsync()
  │                                         │     ├─ 构建 EF Core 查询 (Accounts + PasswordCredentials + UserLogins)
  │                                         │     ├─ query.CountAsync() → total
  │                                         │     └─ ProjectUsersAsync(query, page, pageSize)
  │                                         │        ├─ ToListAsync() → 内存分页
  │                                         │        ├─ OrderByDescending(CreatedAt).Skip().Take()
  │                                         │        └─ 投影为 UserListItemResponse（含 HasPassword）
  │                                         │
  ◀─────────────────────────────────────── Ok(PagedResponse<UserListItemResponse>)
```

### GetUsersByIds
```
Client ──POST /api/gateway/users/batch──▶ GatewayController
  │                                         │
  │  Headers: X-Admin-AppId, X-Admin-AppSecret
  │  Body: ["id1", "id2", ...]             │  1. ValidateGatewayRequestAsync() (同上)
  │                                         │  2. userQueryService.GetUsersByIdsAsync()
  │                                         │     ├─ userIds 为 null/空 → 返回 []
  │                                         │     ├─ 过滤空白、去重(Distinct, OrdinalIgnoreCase)
  │                                         │     ├─ Guid.TryParse → 过滤无效 GUID
  │                                         │     ├─ 查询 Accounts (Where parsedUserIds.Contains)
  │                                         │     ├─ ProjectUsersAsync() → 投影
  │                                         │     ├─ 构建 userMap (UserId → UserListItemResponse)
  │                                         │     └─ 按 orderedUserIds 顺序输出结果
  │                                         │
  ◀─────────────────────────────────────── Ok(List<UserListItemResponse>)
```

## 依赖的数据库表

- [accounts](../../../database/tables/accounts.md)
- [password_credentials](../../../database/tables/password_credentials.md)
- [user_logins](../../../database/tables/user_logins.md)
- [app_registrations](../../../database/tables/app_registrations.md)（网关验证）

## 关键设计决策

1. **内存分页**：`ProjectUsersAsync` 中先 `ToListAsync()` 加载全部过滤结果到内存，再 `OrderByDescending(CreatedAt).Skip().Take()` 分页。这是当前实现方式，在大数据量场景下可能有性能问题
2. **唯一投影实现**：`UserQueryService.ProjectUsersAsync` 是 Admin/Gateway 两端用户查询投影的唯一实现（2026-07-21 收敛，此前两处内联重复），确保管理端和网关端返回一致的用户数据结构
3. **DisplayName 计算规则**：优先使用 Nickname → 其次 Username → 其次 Phone → 最后取 Id 前 8 位
4. **HasPassword 为账户类型唯一判据**：`HasPassword = credentials.ContainsKey(account.Id)`（存在密码凭据即为密码账户）。`Username` 字段对无密码凭据的账户回退为手机号（`username ?? phone`），因此**不能**用 `Username` 是否为空推导账户类型——历史 bug：手机账户的 `Username` 返回手机号，前端据此全部显示为"密码账户"
4. **批量查询保持请求顺序**：通过 `orderedUserIds` 和 `userMap` 确保返回结果按请求中 ID 的顺序排列，不存在的 ID 不出现在结果中
5. **无效 GUID 过滤**：批量查询时，非 GUID 格式的字符串会被 `Guid.TryParse` 过滤，不会导致查询错误
6. **凭证验证**：`GatewayValidationService.ValidateAsync` 依次验证 AppSecret 非空 → AppId 已注册 → App 已激活 → App 未过期 → BCrypt 验证 AppSecret
7. **AppSecret 脱敏中间件**：`X-Admin-AppSecret` 请求头在认证中间件之后被移至 `HttpContext.Items`，防止下游日志/中间件意外记录该值。`GatewayController` 优先从 `HttpContext.Items` 读取，回退到请求头
8. **HTTPS 安全模型**：Gateway API 设计为内部网络调用（Docker `ruoyu-net`）。生产环境必须通过反向代理 TLS 终结或直接启用 HTTPS。非 HTTPS 请求会输出警告日志
