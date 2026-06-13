# 刷新令牌吊销 (RevokeRefreshToken)

## 核心用户故事

作为已登录的用户或管理员，我希望能够吊销刷新令牌，以便在发现安全风险或主动退出时使令牌失效。

## 功能名称和一句话概括

刷新令牌吊销 — 通过 gRPC 接口吊销指定的刷新令牌。

## 补充约束

- 吊销操作不可逆
- 令牌不存在时返回 success=false（不区分"不存在"和"已吊销"）

## 关键验收条件摘要

1. [ ] 有效的 refresh_token 吊销成功，返回 success=true
2. [ ] refresh_token 为空时返回 success=false
3. [ ] refresh_token 不存在时返回 success=false

## 明确列出"范围外"

- 不处理 access_token 的吊销（JWT 无状态，依赖自然过期）
- 不批量吊销某用户的所有令牌（需逐个吊销）

## 文档索引

- [详细需求规格](./02-SPEC.md)
- [设计说明](./03-DESIGN.md)
- [任务清单](./04-TASKS.md)
- [测试计划](./05-TESTS.md)
- [约定与规范](./06-CONVENTIONS.md)
