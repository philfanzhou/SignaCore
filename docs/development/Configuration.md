# 配置参考 (Configuration)

> 本文档列出所有配置项及其来源。配置优先级：环境变量 > appsettings.json > 代码默认值。

## 端口配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Endpoints:Grpc | 5001 | gRPC 监听端口（HTTP/2 only） |
| Endpoints:Http | 5002 | HTTP 监听端口（HTTP/1.1 + HTTP/2） |

## 数据库配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Database:Provider | SQLite | 数据库提供者（SQLite / PostgreSQL） |
| Database:AutoMigrate | true | 是否自动执行迁移 |
| ConnectionStrings:Default | Data Source=quantumzhou_identity.db | SQLite 连接字符串 |
| ConnectionStrings:PostgreSQL | Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres | PostgreSQL 连接字符串 |
| DB_PASSWORD（环境变量） | - | PostgreSQL 密码，自动追加到连接字符串 |

## JWT 配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Jwt:Issuer | QuantumZhou.Identity | JWT 签发者 |
| Jwt:Audience | QuantumZhou.microservices | JWT 受众 |
| Jwt:TokenExpirationHours | 2 | Access Token 有效期（小时） |

## 刷新令牌配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| RefreshToken:ExpirationDays | 7 | 刷新令牌有效期（天） |

## 密码哈希配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| PasswordHasher:WorkFactor | 11 | BCrypt WorkFactor（越高越安全，越慢） |

## 短信 OTP 配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Sms:OtpTtlSeconds | 300 | 验证码有效期（秒） |
| Sms:MaxAttempts | 5 | 最大验证尝试次数 |
| Sms:LockoutSeconds | 600 | 超过最大尝试后锁定时间（秒） |
| Sms:BypassCode | （空） | 绕过验证码（仅限开发/预发布，空值=禁用） |
| SMS_BYPASS_CODE（环境变量） | - | 绕过验证码，优先级高于配置文件 |

## 微信配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| WeChat:AppId | （空） | 微信开放平台 AppId |
| WeChat:AppSecret | （空） | 微信开放平台 AppSecret |
| WeChat:ApiBaseUrl | https://api.weixin.qq.com | 微信 API 基地址 |

## 速率限制配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| RateLimiting:PermitLimitPerClient | 20 | 每个 IP 每窗口允许的请求数 |
| RateLimiting:WindowSeconds | 60 | 速率限制窗口（秒） |
| RateLimiting:CleanupIntervalSeconds | 300 | 清理过期限流记录的间隔（秒） |

## gRPC 配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Grpc:MaxReceiveMessageSize | 4194304 | 最大接收消息大小（4MB） |
| Grpc:MaxSendMessageSize | 4194304 | 最大发送消息大小（4MB） |

## 回调配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Callback:AllowedDomains | [] | 允许的回调域名列表（空=不限制） |
| Callback:AllowPrivateAddresses | true | 是否允许私有 IP 地址回调 |

## 管理员配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| AdminWeb:AdminUsernames | [] | 允许访问管理端的用户名白名单（空=允许所有） |
| AdminWeb:AllowedOrigins | ["http://localhost:5173"] | CORS 允许的前端来源 |
| AdminBootstrap:Username | admin | 初始管理员用户名 |
| AdminBootstrap:Password | （空） | 初始管理员密码（生产环境必须通过环境变量配置） |
| ADMIN_BOOTSTRAP_USERNAME（环境变量） | - | 初始管理员用户名，优先级高于配置文件 |
| ADMIN_BOOTSTRAP_PASSWORD（环境变量） | - | 初始管理员密码，优先级高于配置文件 |

## Teacher Portal 应用注册配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| TeacherPortal:AppId | （空） | Teacher Portal 应用 ID |
| TeacherPortal:AppSecret | （空） | Teacher Portal 应用密钥 |
| TeacherPortal:CallbackUrl | http://localhost:5004/api/auth/callback | 回调 URL |
| TEACHER_PORTAL_APP_ID（环境变量） | - | Teacher Portal 应用 ID，优先级高于配置文件 |
| TEACHER_PORTAL_APP_SECRET（环境变量） | - | Teacher Portal 应用密钥，优先级高于配置文件 |

> 当 AppId 和 AppSecret 均未配置时，服务启动时跳过 Teacher Portal 应用注册并输出警告日志。

## RSA 主密钥

| 来源 | 优先级 | 说明 |
|------|--------|------|
| 环境变量 `RSA_MASTER_KEY` | 最高 | Base64 编码的主密钥 |
| 文件 `master-key/master-key.json` | 中 | 本地文件，格式 `{"Key":"base64..."}` |
| 自动生成 | 最低 | 首次启动时生成并保存到文件 |

## 日志配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Logging:LogLevel:Default | Information | 默认日志级别 |
| Logging:LogLevel:Microsoft.AspNetCore | Warning | ASP.NET Core 日志级别 |
| Logging:LogLevel:Microsoft.EntityFrameworkCore | Warning | EF Core 日志级别 |
| Logging:LogLevel:Grpc | Information | gRPC 日志级别 |
| Logging:Console:FormatterName | json | 控制台日志格式（JSON 结构化） |
