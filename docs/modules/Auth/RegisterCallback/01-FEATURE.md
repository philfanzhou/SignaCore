# 回调注册 (RegisterCallback)

## 核心用户故事

作为业务系统的开发者，我希望注册自己的权限回调地址，以便用户登录时 Identity 服务能回调我的系统获取该用户的角色和权限信息。

## 功能名称和一句话概括

回调注册 — 业务系统通过 HTTP 端点注册权限回调 URL 和有效期。

## 补充约束

- 回调 URL 必须通过 CallbackUrlValidator 验证（协议、域名、IP 限制）
- TTL 为 -1 表示永不过期，否则默认 3600 秒
- AppSecret 使用 BCrypt 验证

## 关键验收条件摘要

1. [ ] 有效的 AppId + AppSecret + CallbackUrl 注册成功
2. [ ] AppId 或 AppSecret 为空时返回错误
3. [ ] AppId 未注册时返回错误
4. [ ] AppSecret 不匹配时返回错误
5. [ ] TTL 为 -1 时回调永不过期

## 明确列出"范围外"

- 不验证 CallbackUrl 的可达性（仅验证格式和域名限制）
- 不处理回调的实际调用（由 GetToken 流程中的 CallbackService 处理）

## 文档索引

- [详细需求规格](./02-SPEC.md)
- [设计说明](./03-DESIGN.md)
- [任务清单](./04-TASKS.md)
- [测试计划](./05-TESTS.md)
- [约定与规范](./06-CONVENTIONS.md)
