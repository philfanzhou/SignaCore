# 应用注册管理 — 详细需求规格 (SPEC)

## 功能概述和用户故事

作为系统管理员，我希望管理业务系统注册信息，以便控制接入身份认证服务的业务系统。

- 用户故事 1：作为管理员，我需要查看所有已注册的应用，以便了解哪些业务系统接入了认证服务
- 用户故事 2：作为管理员，我需要创建新应用并获取 AppSecret，以便将认证能力授权给新业务系统
- 用户故事 3：作为管理员，我需要更新应用的回调配置，以便控制 OAuth 回调行为和有效期
- 用户故事 4：作为管理员，我需要删除不再使用的应用，以便维护系统整洁
- 用户故事 5：作为管理员，我需要重置 AppSecret，以便在密钥泄露时快速轮换
- 用户故事 6：作为管理员，我需要吊销刷新令牌，以便在安全事件时强制用户重新登录
- 用户故事 7：作为管理员，我需要查看审计日志，以便追踪管理操作的完整历史

## 功能要求清单

- [ ] FR-01: 查询应用列表（GET /api/admin/apps）
- [ ] FR-02: 创建应用（POST /api/admin/apps）
- [ ] FR-03: 更新回调配置（PUT /api/admin/apps/{appId}/callback）
- [ ] FR-04: 删除应用（DELETE /api/admin/apps/{appId}）
- [ ] FR-05: 重置 AppSecret（POST /api/admin/apps/{appId}/reset-secret）
- [ ] FR-06: 吊销刷新令牌（POST /api/admin/tokens/revoke）
- [ ] FR-07: 查看审计日志（GET /api/admin/audit-logs）

## 详细的验收标准

### AC-FR-01: 查询应用列表
- **Given** 管理员已登录
- **When** GET /api/admin/apps
- **Then** 返回 200，所有应用按 CreatedAt 降序排列，每条记录包含 AppId、AppName、CallbackUrl、CallbackExpiresAt、IsActive、CreatedAt

### AC-FR-02: 创建应用
- **Given** AppName 不为空
- **When** POST /api/admin/apps
- **Then** 生成 AppId + AppSecret，返回明文 AppSecret

### AC-FR-03: 更新回调配置
- **Given** AppId 存在
- **When** PUT /api/admin/apps/{appId}/callback { callbackUrl, ttlSeconds }
- **Then** 更新 CallbackUrl 和 CallbackExpiresAt；若 CallbackUrl 为空则清除回调地址和过期时间；TtlSeconds=-1 表示永不过期（ExpiresAt=null），TtlSeconds>0 则 ExpiresAt=now+TtlSeconds，其余情况 ExpiresAt=now+3600s

### AC-FR-04: 删除应用
- **Given** AppId 存在
- **When** DELETE /api/admin/apps/{appId}
- **Then** 从数据库中移除应用记录，记录审计日志，返回 200

### AC-FR-05: 重置 AppSecret
- **Given** AppId 存在
- **When** POST /api/admin/apps/{appId}/reset-secret
- **Then** 生成新 AppSecret，旧密钥失效，记录审计日志

### AC-FR-06: 吊销刷新令牌
- **Given** 刷新令牌存在
- **When** POST /api/admin/tokens/revoke { refreshToken }
- **Then** 吊销该令牌，记录审计日志，返回 200

- **Given** 刷新令牌不存在
- **When** POST /api/admin/tokens/revoke { refreshToken }
- **Then** 返回 400

### AC-FR-07: 查看审计日志
> 本端点的唯一事实源为 [Security/AuditLogging](../../Security/AuditLogging/02-SPEC.md)（FR-03），此处仅索引，不重复定义规格。

- **Given** 管理员已登录
- **When** GET /api/admin/audit-logs?action=xxx&targetType=yyy&targetId=zzz&actorId=www&page=1&pageSize=20
- **Then** 返回 200，支持按 action、targetType、targetId、actorId 过滤，分页结果（详见 AuditLogging 模块）

## 非功能需求

| 类别 | 需求 |
|------|------|
| 安全 | AppSecret 使用 BCrypt 哈希存储 |
| 审计 | 删除应用、重置密钥操作记录审计日志 |
| 安全 | AppSecret 生成方式为 Base64(RandomNumberGenerator.GetBytes(32))，确保密码学安全随机 |
| 安全 | AppSecretHash 存储为 BCrypt 哈希值，不可逆，仅用于验证时比对 |

## 测试策略

- [当前无测试覆盖]
