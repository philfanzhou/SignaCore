# 用户昵称管理 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为已登录的用户，我希望查看和修改自己的昵称，以便在系统中使用自定义的显示名称。

- 用户通过 Profile API 查看和修改自己的昵称
- 需要 JWT Bearer 认证（UserProfile 策略）
- 昵称最大长度 100 字符
- 昵称为空字符串时清除昵称
- 不支持修改用户名、手机号等身份信息
- 不支持修改密码

## 功能要求清单

- [ ] FR-01: 获取个人资料（GET /api/profile/me）
- [ ] FR-02: 修改昵称（PATCH /api/profile/nickname）

## 详细的验收标准

### AC-FR-01
- **Given** 有效的 JWT Bearer Token
- **When** GET /api/profile/me
- **Then** 返回 UserId、Nickname、IsActive、CreatedAt

### AC-FR-02
- **Given** 有效的 JWT Bearer Token，昵称不超过 100 字符
- **When** PATCH /api/profile/nickname
- **Then** 更新昵称，返回成功

### AC-FR-02-补充：清除昵称
- **Given** 有效的 JWT Bearer Token
- **When** PATCH /api/profile/nickname，Nickname 为 null 或空白字符串
- **Then** 将数据库中昵称字段设为 null，返回成功

### AC-FR-02-补充：昵称超长
- **Given** 有效的 JWT Bearer Token，昵称超过 100 字符（`IdentityConstants.MaxNicknameLength`）
- **When** PATCH /api/profile/nickname
- **Then** 返回 400 BadRequest，提示 "Nickname cannot exceed 100 characters."

## 非功能需求

- **NFR-01 安全性**：所有接口必须通过 JWT Bearer 认证，且使用 `UserProfile` 授权策略（`[Authorize(Policy = "UserProfile")]`）
- **NFR-02 数据约束**：昵称最大长度 100 字符（由 `IdentityConstants.MaxNicknameLength` 定义）
- **NFR-03 昵称语义**：昵称为 null 表示未设置昵称；空字符串或纯空白字符串等效于清除昵称（设为 null）；非空白昵称会 Trim 后存储

## 测试策略

- 当前无测试覆盖
- 建议优先补充：认证拦截测试、昵称长度校验测试、昵称清除测试
