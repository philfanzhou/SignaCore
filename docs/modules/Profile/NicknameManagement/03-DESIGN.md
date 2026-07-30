# 用户昵称管理 — 设计说明 (DESIGN)

## 文件结构

```
backend/Host/Controllers/ProfileController.cs
backend/Host/Models/AdminModels.cs          (ProfileResponse, UpdateProfileNicknameRequest)
backend/Database/IdentityConstants.cs       (MaxNicknameLength)
```

## 关键接口签名和数据结构定义

```csharp
// ProfileController.cs
[Route("api/profile")]
[ApiController]
[Authorize(Policy = "UserProfile")]
public class ProfileController : ControllerBase
{
    [HttpGet("me")]
    public async Task<IActionResult> GetProfile([FromServices] IAccountRepository accountRepository);

    [HttpPatch("nickname")]
    public async Task<IActionResult> UpdateNickname(
        [FromBody] UpdateProfileNicknameRequest request,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IUnitOfWork unitOfWork);
}

// AdminModels.cs
public sealed record ProfileResponse(
    string UserId,
    string? Nickname,
    bool IsActive,
    long CreatedAt);

public sealed record UpdateProfileNicknameRequest(string? Nickname);
```

## 数据流/调用链

### GetProfile
```
Client ──GET /api/profile/me──▶ ProfileController
  │                                │
  │  [Authorize("UserProfile")]    │  1. GetAccountId() → 从 JWT ClaimTypes.NameIdentifier 解析 accountId
  │                                │  2. accountRepository.GetByIdAsync(accountId)
  │                                │  3. 构造 ProfileResponse(account.Id, account.Nickname, account.IsActive, account.CreatedAt)
  │                                │
  ◀────────────────────────────── Ok(ProfileResponse)
```

### UpdateNickname
```
Client ──PATCH /api/profile/nickname──▶ ProfileController
  │                                       │
  │  [Authorize("UserProfile")]           │  1. GetAccountId() → 从 JWT 解析 accountId
  │                                       │  2. accountRepository.GetByIdAsync(accountId)
  │                                       │  3. 校验 Nickname 长度 ≤ MaxNicknameLength(100)
  │                                       │  4. 赋值: string.IsNullOrWhiteSpace → null, 否则 Trim
  │                                       │  5. accountRepository.UpdateAsync(account)
  │                                       │  6. unitOfWork.SaveChangesAsync()
  │                                       │
  ◀───────────────────────────────────── Ok(AdminOperationResponse)
```

## 依赖的数据库表

- [accounts](../../../database/tables/accounts.md)

## 关键设计决策

1. **昵称 null 语义**：`Nickname` 为 null 表示用户未设置昵称；空字符串或纯空白字符串在更新时会被转换为 null（清除昵称），而非存储为空字符串
2. **Trim 处理**：非空白昵称在存储前会执行 `Trim()` 操作，避免前后空白字符
3. **长度校验**：长度校验基于 Trim 后的字符串，上限由 `IdentityConstants.MaxNicknameLength`（100）定义
4. **JWT 认证**：控制器级别使用 `[Authorize(Policy = "UserProfile")]`，所有接口均需通过认证
5. **AccountId 提取**：从 `ClaimTypes.NameIdentifier` 中解析 Guid，解析失败返回 401
