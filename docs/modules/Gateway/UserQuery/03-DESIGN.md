# 网关用户查询 — 设计说明 (DESIGN)

## 文件结构

```
backend/Host/Controllers/GatewayController.cs
backend/Domain/Services/GatewayValidationService.cs
backend/Host/Models/AdminModels.cs          (AdminUserListItemResponse, AdminPagedResponse, etc.)
backend/Database/IdentityConstants.cs       (AuthMethodSms)
```

## 关键接口签名和数据结构定义

```csharp
// GatewayController.cs
[Route("api/gateway")]
[ApiController]
public class GatewayController : ControllerBase
{
    private const string AppIdHeader = "X-Admin-AppId";
    private const string AppSecretHeader = "X-Admin-AppSecret";

    [HttpGet("users/search")]
    public async Task<IActionResult> SearchUsers(
        [FromQuery] string? username,
        [FromQuery] string? phone,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] GatewayValidationService gatewayValidationService);

    [HttpPost("users/batch")]
    public async Task<IActionResult> GetUsersByIds(
        [FromBody] List<string>? userIds,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] GatewayValidationService gatewayValidationService);
}

// AdminModels.cs
public sealed record AdminPagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed record AdminUserListItemResponse(
    string UserId,
    string Username,
    string Phone,
    bool IsActive,
    string Remark,
    string? Nickname,
    long CreatedAt,
    string DisplayName);
```

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
  │                                         │  3. 构建 EF Core 查询 (Accounts + PasswordCredentials + UserLogins)
  │                                         │  4. query.CountAsync() → total
  │                                         │  5. ProjectUsersAsync(query, dbContext, page, pageSize)
  │                                         │     ├─ ToListAsync() → 内存分页
  │                                         │     ├─ OrderByDescending(CreatedAt).Skip().Take()
  │                                         │     └─ 投影为 AdminUserListItemResponse
  │                                         │
  ◀─────────────────────────────────────── Ok(AdminPagedResponse<AdminUserListItemResponse>)
```

### GetUsersByIds
```
Client ──POST /api/gateway/users/batch──▶ GatewayController
  │                                         │
  │  Headers: X-Admin-AppId, X-Admin-AppSecret
  │  Body: ["id1", "id2", ...]             │  1. ValidateGatewayRequestAsync() (同上)
  │                                         │  2. userIds 为 null/空 → 返回 []
  │                                         │  3. 过滤空白、去重(Distinct, OrdinalIgnoreCase)
  │                                         │  4. Guid.TryParse → 过滤无效 GUID
  │                                         │  5. 查询 Accounts (Where parsedUserIds.Contains)
  │                                         │  6. ProjectUsersAsync() → 投影
  │                                         │  7. 构建 userMap (UserId → AdminUserListItemResponse)
  │                                         │  8. 按 orderedUserIds 顺序输出结果
  │                                         │
  ◀─────────────────────────────────────── Ok(List<AdminUserListItemResponse>)
```

## 依赖的数据库表

- [accounts](../../database/tables/accounts.md)
- [password_credentials](../../database/tables/password_credentials.md)
- [user_logins](../../database/tables/user_logins.md)
- [app_registrations](../../database/tables/app_registrations.md)（网关验证）

## 关键设计决策

1. **内存分页**：`ProjectUsersAsync` 中先 `ToListAsync()` 加载全部过滤结果到内存，再 `OrderByDescending(CreatedAt).Skip().Take()` 分页。这是当前实现方式，在大数据量场景下可能有性能问题
2. **相同投影逻辑**：`ProjectUsersAsync` 方法与 AdminController 使用相同的投影逻辑，生成 `AdminUserListItemResponse`，确保管理端和网关端返回一致的用户数据结构
3. **DisplayName 计算规则**：优先使用 Nickname → 其次 Username → 其次 Phone → 最后取 Id 前 8 位
4. **批量查询保持请求顺序**：通过 `orderedUserIds` 和 `userMap` 确保返回结果按请求中 ID 的顺序排列，不存在的 ID 不出现在结果中
5. **无效 GUID 过滤**：批量查询时，非 GUID 格式的字符串会被 `Guid.TryParse` 过滤，不会导致查询错误
6. **凭证验证**：`GatewayValidationService.ValidateAsync` 依次验证 AppSecret 非空 → AppId 已注册 → App 已激活 → App 未过期 → BCrypt 验证 AppSecret
7. **AppSecret 脱敏中间件**：`X-Admin-AppSecret` 请求头在认证中间件之后被移至 `HttpContext.Items`，防止下游日志/中间件意外记录该值。`GatewayController` 优先从 `HttpContext.Items` 读取，回退到请求头
8. **HTTPS 安全模型**：Gateway API 设计为内部网络调用（Docker `ruoyu-net`）。生产环境必须通过反向代理 TLS 终结或直接启用 HTTPS。非 HTTPS 请求会输出警告日志
