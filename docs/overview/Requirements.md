# 服务级需求 (Requirements)

## 核心需求摘要

| 编号 | 需求 | 详细文档 |
|------|------|----------|
| REQ-01 | 支持多种登录方式（密码/短信/微信/刷新令牌） | [modules/Auth/GetToken/01-FEATURE.md](../modules/Auth/GetToken/01-FEATURE.md) |
| REQ-02 | 业务系统注册和回调权限注入 | [modules/Auth/RegisterCallback/01-FEATURE.md](../modules/Auth/RegisterCallback/01-FEATURE.md) |
| REQ-03 | 刷新令牌吊销 | [modules/Auth/RevokeRefreshToken/01-FEATURE.md](../modules/Auth/RevokeRefreshToken/01-FEATURE.md) |
| REQ-04 | 管理员用户管理 | [modules/Admin/UserManagement/01-FEATURE.md](../modules/Admin/UserManagement/01-FEATURE.md) |
| REQ-05 | 管理员应用注册管理 | [modules/Admin/AppManagement/01-FEATURE.md](../modules/Admin/AppManagement/01-FEATURE.md) |
| REQ-06 | 网关用户查询 | [modules/Gateway/UserQuery/01-FEATURE.md](../modules/Gateway/UserQuery/01-FEATURE.md) |
| REQ-07 | 用户个人资料管理 | [modules/Profile/NicknameManagement/01-FEATURE.md](../modules/Profile/NicknameManagement/01-FEATURE.md) |
| REQ-08 | RSA 密钥管理和自动轮换 | [modules/Security/KeyManagement/01-FEATURE.md](../modules/Security/KeyManagement/01-FEATURE.md) |
| REQ-09 | 过期数据自动清理 | [modules/Security/DataCleanup/01-FEATURE.md](../modules/Security/DataCleanup/01-FEATURE.md) |
| REQ-10 | 审计日志记录 | [modules/Security/AuditLogging/01-FEATURE.md](../modules/Security/AuditLogging/01-FEATURE.md) |

## 非功能需求

| 类别 | 需求 | 说明 |
|------|------|------|
| 性能 | 登录响应时间 | 通过 `auth.login.duration` 指标监控 |
| 安全 | 密码存储 | BCrypt 哈希，WorkFactor 可配置 |
| 安全 | 私钥保护 | AES-GCM 加密存储，主密钥来自环境变量 |
| 安全 | 防暴力破解 | 登录失败锁定 + 速率限制 |
| 可靠性 | 回调失败降级 | 不阻塞登录，继续签发基本 JWT |
| 可观测性 | OpenTelemetry | 指标 + 追踪，Prometheus 端点 |
| 可观测性 | 结构化日志 | JSON 格式，含 CorrelationId |

## 业务规则

| 规则项 | 说明 |
|--------|------|
| 访问令牌有效期 | 默认 2 小时 |
| 刷新令牌有效期 | 默认 7 天 |
| 密码最小长度 | 8 个字符 |
| 密码复杂度要求 | 大写字母 + 小写字母 + 数字 |
| 短信验证码有效期 | 默认 5 分钟（300 秒） |
| 验证码最大错误次数 | 默认 5 次 |
| 验证码错误锁定时间 | 默认 10 分钟（600 秒） |
| 密码错误锁定次数 | 默认多次后锁定 |
| 请求频率限制 | 每个客户端每分钟最多 20 次请求 |
| 加密密钥轮换周期 | 默认定期自动更换 |

## 术语

| 术语 | 解释 |
|------|------|
| 访问令牌（Access Token） | 用户登录成功后获得的"通行证"，有效期内可用来访问业务系统 |
| 刷新令牌（Refresh Token） | 用来获取新的访问令牌的"续期凭证"，避免频繁输入密码 |
| AppId / AppSecret | 业务系统的"身份证"和"密码"，用于证明业务系统的身份 |
| 回调地址（Callback URL） | 业务系统提供的一个网址，身份认证系统通过它向业务系统询问用户权限 |
| 角色（Role） | 用户在业务系统中的身份类型，如"管理员"、"普通用户"等 |
| 权限（Permission） | 用户在业务系统中可以执行的操作，如"查看数据"、"删除数据"等 |
| 登录方式（Grant Type） | 用户验证身份的方式，如密码登录、短信登录等 |
