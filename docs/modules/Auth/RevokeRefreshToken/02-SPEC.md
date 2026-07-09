# 刷新令牌吊销 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为已登录的用户或管理员，我希望能够吊销刷新令牌，以便在安全风险或退出时使令牌失效。

## 功能要求清单

- [ ] FR-01: 验证 refresh_token 不为空
- [ ] FR-02: 查找令牌并标记为已撤销

## 详细的验收标准

### AC-FR-01: 参数验证
- **Given** RevokeRequest
- **When** refresh_token 为空
- **Then** 返回 success=false

### AC-FR-02: 吊销成功
- **Given** 数据库中存在有效的 refresh_token
- **When** 调用 RevokeRefreshToken
- **Then** 令牌 IsRevoked=true，返回 success=true

### AC-FR-03: 令牌不存在
- **Given** 数据库中不存在该 refresh_token
- **When** 调用 RevokeRefreshToken
- **Then** 返回 success=false

## 非功能需求

| 类别 | 需求 |
|------|------|
| 安全 | 不区分"不存在"和"已吊销"，防止信息泄露 |

## 测试策略

- 单元测试覆盖空参数、存在令牌、不存在令牌场景
- [当前无测试覆盖]
