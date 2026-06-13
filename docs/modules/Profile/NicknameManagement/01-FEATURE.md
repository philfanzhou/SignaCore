# 用户昵称管理 (NicknameManagement)

## 核心用户故事

作为已登录的用户，我希望查看和修改自己的昵称，以便在系统中使用自定义的显示名称。

## 功能名称和一句话概括

用户昵称管理 — 用户通过 Profile API 查看和修改自己的昵称。

## 补充约束

- 需要 JWT Bearer 认证（UserProfile 策略）
- 昵称最大长度 100 字符
- 昵称为空字符串时清除昵称

## 关键验收条件摘要

1. [ ] 查看个人资料（GET /api/profile/me）
2. [ ] 修改昵称（PATCH /api/profile/nickname）

## 明确列出"范围外"

- 不支持修改用户名、手机号等身份信息
- 不支持修改密码

## 文档索引

- [详细需求规格](./02-SPEC.md)
- [设计说明](./03-DESIGN.md)
- [任务清单](./04-TASKS.md)
- [测试计划](./05-TESTS.md)
- [约定与规范](./06-CONVENTIONS.md)
