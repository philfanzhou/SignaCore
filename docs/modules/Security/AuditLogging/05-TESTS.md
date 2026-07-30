# 审计日志记录 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：test/Domain/Services/AuditServiceTests.cs

## 单元测试

### UT-01 记录登录事件

- **Given** 登录事件数据
- **When** 调用 RecordLoginAsync
- **Then** 写入 login_histories 表

### UT-02 记录管理操作

- **Given** 操作数据含 before/after 快照
- **When** 调用 RecordActionAsync
- **Then** 写入 audit_logs 表，快照为 camelCase JSON

### UT-03 写入失败不抛异常

- **Given** 数据库写入失败
- **When** 调用 RecordLoginAsync
- **Then** 记录 LogError，不抛异常
