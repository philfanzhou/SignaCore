# 统一 Token 获取 (GetToken)

## 核心用户故事

作为业务系统的用户，我希望通过统一的接口使用不同的登录方式（密码/短信/微信/刷新令牌）进行认证，以便获得访问业务系统的 JWT 令牌。

## 功能名称和一句话概括

统一 Token 获取 — 通过 OAuth2 grant_type 模式支持多种认证方式获取 JWT。

## 补充约束

- 回调权限注入失败不阻塞登录流程，降级为仅包含基本身份信息的 JWT
- 刷新令牌使用时旧令牌立即失效（一次性使用），同时签发新令牌
- 密码登录连续失败 5 次后锁定账户 15 分钟
- 短信验证码有 5 分钟有效期，最多验证 5 次
- 微信登录不支持自动注册，必须预先绑定
- 所有请求可通过 AppId/AppSecret 进行网关验证
- **Bootstrap Admin 角色**：`AdminBootstrap:Username` 配置的 bootstrap admin 账号是"超级管理员"，无论从哪个 portal 登录都应获得 `role:admin`。注入前检查是否已存在 role=admin，避免重复。角色判断规则：
  - **password grant**：使用已通过密码验证的 `request.Username` 与 `AdminBootstrap:Username` 比较（大小写不敏感、配置非空）。
  - **refresh_token grant**：使用 RefreshTokenValidator 已验证出的 `AccountEntity.Id`，与 `AdminBootstrap:Username` 对应的密码账户 ID 比较；**不**读取 refresh 请求体中的 `username`，避免普通账户伪造 `username=admin` 提权。
  - **sms/wechat_code grant**：不触发 bootstrap admin 注入。
  - 绕过 callback 机制，但 callback 已返回 `role=admin` 时不重复添加。

## 关键验收条件摘要

1. [ ] 密码登录：正确的用户名密码返回 access_token 和 refresh_token
2. [ ] 密码登录：错误密码返回 "Wrong username or password"
3. [ ] 密码登录：账户被锁定时返回锁定截止时间
4. [ ] 短信登录：正确的验证码返回 token，首次登录自动注册
5. [ ] 微信登录：有效的 code 返回 token；未绑定返回错误
6. [ ] 刷新令牌：有效的 refresh_token 返回新 token 对，旧 token 失效
7. [ ] 刷新令牌：已撤销或过期的 refresh_token 返回错误
8. [ ] 网关验证：无效的 AppId/AppSecret 返回错误
9. [ ] 回调权限注入：成功时 JWT 包含角色和权限；失败时 JWT 仅包含基本信息
10. [ ] 不支持的 grant_type 返回 "unsupported_grant_type"
11. [ ] Bootstrap Admin 角色（password grant）：登录用户名匹配 `AdminBootstrap:Username` 时，JWT 包含 role:admin（无论 callback 是否返回该角色、无论从何 portal 登录）
12. [ ] Bootstrap Admin 角色（refresh_token grant）：当 refresh_token 对应的已验证账户是 `AdminBootstrap:Username` 对应账户时，新 JWT 必须继续包含 role:admin（不依赖 refresh 请求体中的 username）
13. [ ] 普通账户伪造提权防护：普通账户即使在 refresh 请求体中附带 `username=admin`，也不能获得 `role=admin`
14. [ ] SMS/微信 grant 边界：sms/wechat_code grant 即使账户恰好是 bootstrap account，也不因本次修改自动获得管理员角色
15. [ ] Bootstrap Admin 角色去重：callback 已返回 `role=admin` 时，JWT claims 中 `role=admin` 只出现一次

## 明确列出"范围外"

- 不处理用户注册（密码用户由管理员创建，短信用户自动注册）
- 不处理微信账号绑定（需通过其他渠道预先绑定）
- 不处理短信发送（当前使用 LoggingSmsSender，仅记录日志）
- 不处理 OTP 生成和发送（通过独立的 OtpService 处理，GetToken 只验证）

## 文档索引

- [详细需求规格](./02-SPEC.md)
- [设计说明](./03-DESIGN.md)
- [任务清单](./04-TASKS.md)
- [测试计划](./05-TESTS.md)
- [约定与规范](./06-CONVENTIONS.md)
