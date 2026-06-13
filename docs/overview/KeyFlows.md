# 关键流程 (KeyFlows)

## 1. 密码登录流程

```
触发条件：客户端通过 Gateway 调用 GetToken(grant_type=password)

Client          Gateway        AuthServiceImpl     PasswordValidator    AuditService     DB
  │                │                │                    │                  │             │
  │──GetToken─────▶│                │                    │                  │             │
  │                │──GetToken─────▶│                    │                  │             │
  │                │                │──ValidateGateway──▶│                  │             │
  │                │                │◀──OK───────────────│                  │             │
  │                │                │──ValidateAsync───▶│                  │             │
  │                │                │                    │──GetByUsername─▶│             │
  │                │                │                    │◀──credential────│             │
  │                │                │                    │──VerifyPassword─▶│            │
  │                │                │                    │◀──OK────────────│             │
  │                │                │◀──Success─────────│                  │             │
  │                │                │──BuildClaims──────┐│                  │             │
  │                │                │◀──────────────────┘│                  │             │
  │                │                │──EnrichCallback───▶│BusinessService   │             │
  │                │                │◀──Claims───────────│                  │             │
  │                │                │──GenerateJwt──────┐│                  │             │
  │                │                │◀──────────────────┘│                  │             │
  │                │                │──GenRefreshToken─▶│                  │             │
  │                │                │◀──token───────────│                  │             │
  │                │                │──RecordLogin───────│────────────────▶│             │
  │                │                │──UpdateLoginInfo──│────────────────▶│             │
  │                │◀──TokenResponse│                    │                  │             │
  │◀──TokenResponse│                │                    │                  │             │
```

参与服务：Gateway → AuthServiceImpl → PasswordValidator → CallbackService → AuditService
数据流转：credential 查询 → 密码验证 → Claims 构建 → 回调权限注入 → JWT 签发 → RefreshToken 生成 → 审计记录

## 2. 短信验证码登录流程

```
触发条件：客户端调用 GetToken(grant_type=sms)

Client      AuthServiceImpl     SmsValidator      OtpService      AccountRepo      DB
  │              │                   │                │               │             │
  │──GetToken───▶│                   │                │               │             │
  │              │──ValidateAsync───▶│                │               │             │
  │              │                   │──VerifyAsync──▶│               │             │
  │              │                   │◀──verified─────│               │             │
  │              │                   │──GetByProvider────────────────▶│             │
  │              │                   │                │               │──query─────▶│
  │              │                   │◀──null─────────────────────────│             │
  │              │                   │──AutoRegister─▶│               │             │
  │              │                   │  (Create Account + UserLogin) │             │
  │              │◀──Success────────│                │               │             │
  │              │──(BuildClaims + JWT + RefreshToken + Audit)       │             │
  │◀──TokenResponse│                │                │               │             │
```

关键点：短信登录支持自动注册，首次登录自动创建账户和 UserLogin 绑定。

## 3. 回调权限注入流程

```
触发条件：登录成功且请求的 AppId 对应的业务系统注册了 CallbackUrl

AuthServiceImpl     CallbackService      BusinessService
      │                   │                    │
      │──EnrichClaims───▶│                    │
      │                   │──ValidateUrl──────┐│
      │                   │◀──────────────────┘│
      │                   │──POST /callback───▶│
      │                   │   {user_id: "xxx"} │
      │                   │◀──{roles,perms}────│
      │                   │──ParseClaims──────┐ │
      │                   │◀──────────────────┘│
      │◀──Claims──────────│                    │
```

失败语义：回调失败不阻塞登录，JWT 仅包含基本身份信息。

## 4. 密钥轮换流程

```
触发条件：CleanupWorker 定期检查（每 24 小时），当前密钥即将过期

CleanupWorker      KeyManager         SecurityKeyRepo       DB
      │                 │                   │               │
      │──NeedsRotation─▶│                   │               │
      │                 │──GetLatestKey────▶│──query───────▶│
      │                 │◀──expired─────────│◀──────────────│
      │◀──true──────────│                   │               │
      │──RotateKey─────▶│                   │               │
      │                 │──DeactivateOld───▶│──update──────▶│
      │                 │──GenerateNew─────▶│──insert──────▶│
      │                 │──Encrypt+Save────▶│               │
      │                 │──UpdateCurrent───┐│               │
      │                 │◀─────────────────┘│               │
```

关键点：新密钥使用 AES-GCM 加密后存储，轮换期间服务不中断。

## 5. 管理员登录流程

```
触发条件：管理员通过 Admin Frontend 登录

AdminFrontend      AdminController      ValidatorFactory      PasswordValidator
      │                  │                      │                    │
      │──POST /session/login──────────────────▶│                    │
      │                  │──GetValidator───────▶│                    │
      │                  │◀──PasswordValidator──│                    │
      │                  │──ValidateAsync──────────────────────────▶│
      │                  │◀──Success────────────────────────────────│
      │                  │──CheckAdminAllowed──┐│                    │
      │                  │◀────────────────────┘│                    │
      │                  │──SignInCookie───────┐│                    │
      │                  │◀────────────────────┘│                    │
      │◀──200 + Cookie──│                      │                    │
```

关键点：管理员登录使用 Cookie 认证（非 JWT），需验证用户名在 AdminUsernames 白名单中（白名单为空时允许所有用户）。
