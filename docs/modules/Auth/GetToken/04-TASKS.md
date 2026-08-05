# 统一 Token 获取 — 任务清单 (TASKS)

> 本功能已实现完成，无待办任务。以下为代码评审清单。

```json
[
  {
    "id": "TASK-01",
    "status": "implemented",
    "depends_on": [],
    "action": "GetToken HTTP 端点实现（网关验证 + 验证器分发 + JWT 签发）",
    "files": ["backend/Host/Controllers/AuthController.cs"],
    "acceptance": "密码/短信/微信/刷新令牌四种 grant_type 均可正常获取 token"
  },
  {
    "id": "TASK-02",
    "status": "implemented",
    "depends_on": [],
    "action": "PasswordValidator 密码登录验证（含锁定机制）",
    "files": ["backend/Domain/Validators/PasswordValidator.cs"],
    "acceptance": "正确密码登录成功；错误密码累计失败；达到上限锁定"
  },
  {
    "id": "TASK-03",
    "status": "implemented",
    "depends_on": [],
    "action": "SmsValidator 短信登录验证（含自动注册）",
    "files": ["backend/Domain/Validators/SmsValidator.cs"],
    "acceptance": "验证码正确登录成功；首次登录自动注册"
  },
  {
    "id": "TASK-04",
    "status": "implemented",
    "depends_on": [],
    "action": "WechatValidator 微信登录验证",
    "files": ["backend/Domain/Validators/WechatValidator.cs"],
    "acceptance": "有效 code 登录成功；未绑定返回错误"
  },
  {
    "id": "TASK-05",
    "status": "implemented",
    "depends_on": [],
    "action": "RefreshTokenValidator 刷新令牌验证（含 AppId 匹配）",
    "files": ["backend/Domain/Validators/RefreshTokenValidator.cs"],
    "acceptance": "有效 token 刷新成功；AppId 不匹配拒绝"
  },
  {
    "id": "TASK-06",
    "status": "implemented",
    "depends_on": [],
    "action": "CallbackService 回调权限注入",
    "files": ["backend/Domain/CallbackService.cs"],
    "acceptance": "回调成功注入 claims；回调失败降级为基本 JWT"
  },
  {
    "id": "TASK-09",
    "status": "implemented",
    "depends_on": ["TASK-01", "TASK-05"],
    "action": "Bootstrap admin refresh 角色保持：将 InjectBootstrapAdminRole 改为异步 InjectBootstrapAdminRoleAsync，注入 IAccountRepository；refresh_token grant 使用已验证 AccountEntity.Id 与 AdminBootstrap:Username 对应账户 ID 比较，不读取请求体 username；sms/wechat_code grant 不触发注入",
    "files": [
      "backend/Host/Controllers/AuthController.cs",
      "backend/Tests/unit/Host/Controllers/AuthControllerTests.cs"
    ],
    "acceptance": [
      "Bootstrap admin 密码登录 JWT 包含且仅包含一个 role=admin",
      "Bootstrap admin 使用 Refresh Token 换票后新 JWT 仍包含且仅包含一个 role=admin",
      "普通账户 refresh 请求附带 username=admin 不能获得 role=admin",
      "SMS/微信 grant 即使账户是 bootstrap account 也不注入 role=admin",
      "AdminBootstrap:Username 为空时不注入 role=admin",
      "callback 已返回 role=admin 时不重复添加"
    ]
  },
  {
    "id": "TASK-07",
    "status": "done",
    "depends_on": [],
    "action": "绕过码不是遗留，生产依赖它（ThrowingSmsSender 发不出真实短信），但原实现对任意手机号生效且值硬编码在 public repo 的 start.sh 里，等于万能口令。已改为：绕过码必须配合 Sms:BypassPhones 白名单，白名单为空即整体禁用；绕过码与管理员密码从部署脚本移除，改由 CI 密钥库注入",
    "files": [
      "backend/Domain/Validators/SmsValidator.cs",
      "backend/Domain/Services/Sms/SmsOptions.cs",
      "backend/Host/ServiceCollectionExtensions.cs",
      "start.sh",
      "backend/Tests/unit/Domain/SmsValidatorTests.cs"
    ],
    "acceptance": [
      "白名单内号码 + 绕过码 → 成功且不调用 IOtpService.VerifyAsync",
      "白名单外号码 + 绕过码 → 落回 OTP 校验并失败，不自动注册账号",
      "配了绕过码但白名单为空 → 绕过禁用",
      "start.sh 缺少 ADMIN_BOOTSTRAP_PASSWORD / SMS_BYPASS_CODE / SMS_BYPASS_PHONES 时在停止旧容器之前退出"
    ]
  },
  {
    "id": "TASK-08",
    "status": "to_review",
    "depends_on": [],
    "action": "GatewayValidationService.ValidateAsync 返回的 AccountEntity 是空构造的（Id=Guid.Empty），仅用于表示验证成功",
    "files": ["backend/Domain/Services/GatewayValidationService.cs:L49"],
    "acceptance": "确认此设计是否合理，是否应返回 null 或专用结果类型"
  }
]
```
