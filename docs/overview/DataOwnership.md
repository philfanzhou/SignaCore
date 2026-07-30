# 数据主责 (DataOwnership)

## 本服务拥有的数据实体（主责）

以下表由本服务直接写入和管理：

| 实体 | 表名 | 写入场景 |
|------|------|----------|
| AccountEntity | accounts | 用户注册、管理员创建、登录信息更新 |
| PasswordCredentialEntity | password_credentials | 管理员创建用户、Bootstrap 初始化 |
| UserLoginEntity | user_logins | 短信自动注册、管理员创建手机用户 |
| RefreshTokenEntity | refresh_tokens | 登录成功签发、刷新令牌、吊销 |
| AppRegistrationEntity | app_registrations | 管理员创建/更新/删除应用、Bootstrap 初始化 |
| SecurityKeyEntity | security_keys | 密钥轮换、初始化 |
| OtpEntity | otps | OTP 生成、验证、失效 |
| LoginAttemptEntity | login_attempts | 密码登录失败记录、成功后删除 |
| LoginHistoryEntity | login_histories | 登录成功/失败审计记录 |
| AuditLogEntity | audit_logs | 管理操作审计记录 |

## 本服务引用的外部数据（只读引用）

| 数据 | 来源 | 引用方式 | 说明 |
|------|------|----------|------|
| WeChat OpenId | WeChat Open Platform API | HTTP 调用 | 微信登录时通过 code 换取 OpenId |
| Business Roles/Permissions | Business Service Callback | HTTP 调用 | 登录后回调获取，注入 JWT |

## 禁止写入

本服务绝对不直接写入以下外部系统的数据：
- 业务微服务的数据库（角色和权限由业务系统通过回调提供，本服务不写入）
- WeChat 平台的数据（本服务仅读取 OpenId，不修改微信侧数据）

## 数据清理策略

| 数据 | 保留期 | 清理方式 |
|------|--------|----------|
| RefreshToken | 过期后 | `CleanupWorker` 清理过期和已撤销的令牌 |
| Otp | 验证成功后立即删除 | `DbOtpService.VerifyAsync` |
| LoginAttempt | 登录成功后删除；超过 1 天的过期记录 | `PasswordValidator` / `CleanupWorker` |
| LoginHistory | 90 天 | `CleanupWorker.RemoveOlderThanAsync` |
| AuditLog | 365 天 | `CleanupWorker.RemoveOlderThanAsync` |
| SecurityKey | 过期且非活跃 | `CleanupWorker.RemoveExpiredInactiveAsync` |
| AppRegistration Callback | 过期后标记为不活跃 | `CleanupWorker.DeactivateExpiredCallbacksAsync` |
