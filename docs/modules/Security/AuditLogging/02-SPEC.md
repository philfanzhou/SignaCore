# 审计日志记录 — 详细需求规格 (SPEC)

## 功能概述和用户故事

本模块负责记录系统中的登录事件和管理操作，提供完整的审计追踪能力。登录事件记录到 `login_histories` 表，管理操作记录到 `audit_logs` 表（含变更前后的数据快照），管理员可通过 API 查询审计日志。

**用户故事：**

- **US-01**: 作为安全审计人员，我需要记录每次登录事件（成功/失败），包括账号、认证方式、客户端信息等，以便追踪异常登录行为。
- **US-02**: 作为系统管理员，我需要记录所有管理操作的变更前后快照，以便在出现问题时回溯操作历史。
- **US-03**: 作为管理员，我需要通过 API 按条件查询审计日志，支持分页，以便高效检索特定操作记录。

## 功能要求清单

- [ ] FR-01: 记录登录事件（成功/失败）
- [ ] FR-02: 记录管理操作（含 before/after 快照）
- [ ] FR-03: 查询审计日志（GET /api/admin/audit-logs）

## 详细的验收标准

### AC-FR-01: 记录登录事件
- **Given** 用户尝试登录
- **When** 调用 `RecordLoginAsync`
- **Then** 写入 `login_histories` 表，包含以下字段：accountId、username、authMethod、eventType、clientIp、userAgent、failureReason（失败时）、appId、correlationId

### AC-FR-02: 记录管理操作
- **Given** 管理员执行数据变更操作
- **When** 调用 `RecordActionAsync`
- **Then** 写入 `audit_logs` 表，包含 action、targetType、targetId、actorId、actorName、description、clientIp、correlationId，before/after 快照以 camelCase JSON 格式存储

### AC-FR-03: 查询审计日志
> 本端点规格的唯一事实源在此；Admin/AppManagement/02-SPEC.md 的 FR-07 仅为索引引用。

- **Given** 管理员需要检索审计记录
- **When** 请求 `GET /api/admin/audit-logs`
- **Then** 支持按 action、targetType、targetId、actorId 筛选，支持分页返回结果

## 非功能需求

| 需求项 | 说明 |
|--------|------|
| 写入失败处理 | 审计写入失败仅记录错误日志，不抛出异常，不影响业务操作 |
| 登录历史保留期 | 90 天 |
| 审计日志保留期 | 365 天 |

## 测试策略

- 单元测试：`test/Domain/Services/AuditServiceTests.cs`
  - 验证 RecordLoginAsync 正确写入 login_histories
  - 验证 RecordActionAsync 正确写入 audit_logs 并包含 before/after 快照
  - 验证写入失败时不抛出异常
