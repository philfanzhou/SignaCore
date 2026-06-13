# 用户管理 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Host/
│   ├── Controllers/AdminController.cs     # Admin API 控制器
│   ├── Models/AdminModels.cs              # 请求/响应模型
│   ├── AdminBootstrapOptions.cs           # Bootstrap 配置
│   └── AdminWebOptions.cs                 # 管理端配置
├── Domain/
│   ├── Validators/PasswordValidator.cs    # 管理员登录验证
│   ├── Validators/IPasswordPolicy.cs      # 密码策略
│   └── Services/AuditService.cs           # 审计日志
└── Database/
    ├── Entity/AccountEntity.cs
    ├── Entity/PasswordCredentialEntity.cs
    ├── Entity/UserLoginEntity.cs
    └── Repositories/IRepositories.cs
```

## 关键接口签名

```csharp
[HttpPost("session/login")] Task<IActionResult> Login(AdminLoginRequest request);
[HttpGet("session/me")] Task<IActionResult> GetCurrentSession();
[HttpPost("session/logout")] Task<IActionResult> Logout();
[HttpGet("users")] Task<IActionResult> GetUsers(string? username, string? phone, int? page, int? pageSize);
[HttpPost("users")] Task<IActionResult> CreateUser(AdminCreateUserRequest request);
[HttpPost("users/phone")] Task<IActionResult> CreatePhoneUser(AdminCreatePhoneUserRequest request);
[HttpPatch("users/{userId:guid}/remark")] Task<IActionResult> UpdateUserRemark(Guid userId, AdminUpdateRemarkRequest request);
[HttpPatch("users/{userId:guid}/nickname")] Task<IActionResult> UpdateUserNickname(Guid userId, AdminUpdateNicknameRequest request);
[HttpPatch("users/{userId:guid}/status")] Task<IActionResult> UpdateUserStatus(Guid userId, AdminUpdateStatusRequest request);
[HttpGet("users/{userId:guid}/login-history")] Task<IActionResult> GetUserLoginHistory(Guid userId, int? page, int? pageSize);
```

## 依赖的数据库表

- [accounts](../../database/tables/accounts.md)
- [password_credentials](../../database/tables/password_credentials.md)
- [user_logins](../../database/tables/user_logins.md)
- [login_histories](../../database/tables/login_histories.md)
- [audit_logs](../../database/tables/audit_logs.md)

## 数据流/调用链

### 管理员登录流程

```
Request (username, password, rememberMe)
  │
  ▼
ValidatorFactory.GetValidator(password)
  │
  ▼
PasswordValidator.ValidateAsync(username, password)
  │
  ▼
IsAdminUsernameAllowed(username)  ─── 白名单为空 → 允许所有
  │                                 白名单非空 → 仅允许列表中用户
  ├── 不允许 → 返回 403
  │
  ▼
SignInAsync(Cookie: qz_admin_session)
  │  - 添加 admin_access claim
  │  - 滑动过期 12h / 7d (rememberMe)
  │
  ▼
AuditService.RecordLoginAsync(action=admin_login)
  │
  ▼
Response 200
```

## 关键设计决策

| 决策 | 说明 |
|------|------|
| 管理员认证使用 Cookie（非 JWT） | 管理端为浏览器场景，Cookie 更安全（HttpOnly 防 XSS），且携带 admin_access claim 用于鉴权中间件校验 |
| AdminUsernames 白名单策略 | 配置为空数组时允许所有用户登录管理端；非空时仅允许列表中的用户名登录 |
| GetUsers 内存分页 | 由于 EF Core 子查询限制，查询用户列表时先 ToList() 加载到内存，再 Skip/Take 分页 |
| Admin Session Cookie 安全属性 | HttpOnly=true、SameSite=Lax、SecurePolicy=SameAsRequest，防止 XSS 和 CSRF |
