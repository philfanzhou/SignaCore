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
    "id": "TASK-07",
    "status": "to_review",
    "depends_on": [],
    "action": "SmsValidator 中硬编码 bypass code '666666'，需确认是否为测试遗留",
    "files": ["backend/Domain/Validators/SmsValidator.cs:L44-45"],
    "acceptance": "确认 bypass code 的用途，生产环境是否需要移除"
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
