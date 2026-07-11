# 配置参考 (Configuration)

> 本文档列出所有配置项及其来源。
>
> **当前部署脚本优先级**：命令行 > 环境变量 > Consul KV（`_global` → `_shared` → `QuantumZhou.Identity`）> 本地缓存 > appsettings.{Env} > appsettings.json
>
> 详见 [ConsulIntegration.md](./ConsulIntegration.md)

## Consul 集成配置

| 配置键 | 环境变量 | 默认值 | 说明 |
|--------|---------|--------|------|
| `Consul:Mode` | `CONSUL_MODE` | `On`（由 `start.sh` 固定注入） | Identity 部署脚本始终以 Consul 模式启动 |
| `Consul:Host` | `CONSUL_HOST` | `host.docker.internal` | Consul HTTP API 地址 |
| `Consul:Port` | `CONSUL_PORT` | `8500` | Consul HTTP API 端口 |
| `Consul:ServiceName` | `CONSUL_SERVICE_NAME` | `QuantumZhou.Identity` | 注册到 Consul 的服务名称 |
| `Consul:ServiceId` | `CONSUL_SERVICE_ID` | 自动生成 | 服务实例 ID（多实例需唯一）|
| `Consul:KvPrefix` | `CONSUL_KV_PREFIX` | `config/ruoyu` | KV 路径前缀 |
| `Consul:Profile` | `CONSUL_PROFILE` | 与 `ASPNETCORE_ENVIRONMENT` 一致 | KV 路径中的环境段 |
| `Consul:TimeoutMs` | `CONSUL_TIMEOUT_MS` | `3000` | 单次请求超时（毫秒） |
| `Consul:RetryCount` | `CONSUL_RETRY_COUNT` | `3` | 连接重试次数（指数退避） |
| `Consul:EnableCache` | `CONSUL_ENABLE_CACHE` | `true` | 是否启用本地缓存兜底 |
| `Consul:Token` | `CONSUL_TOKEN` | （空） | Consul ACL token（启用 ACL 时必需） |

> Consul 配置的详细语义、启动时序、缓存机制、KV 分层策略请见 [ConsulIntegration.md](./ConsulIntegration.md)。
>
> **当前约束**：Identity 启动脚本不再注入数据库主机、端口、用户名、密码、Provider、数据库名和 Loki 地址；这些配置统一由 Consul KV 提供。`RSA_MASTER_KEY`、管理员引导密码、AppSecret 等启动密钥仍保留在环境变量或文件。

---

## 端口配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Endpoints:Http | 5002 | HTTP 监听端口（业务/认证，HTTP/1.1 + HTTP/2） |

## 数据库配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Database:Provider | SQLite | 数据库提供者（SQLite / PostgreSQL） |
| Database:Name | quantumzhou_identity | 服务自己的 PostgreSQL 数据库名（仅在使用共享 PostgreSql 主机配置时参与拼接） |
| Database:AutoMigrate | true | 是否自动执行迁移（生产环境建议设为 false） |
| ConnectionStrings:Default | Data Source=quantumzhou_identity.db | SQLite 连接字符串 |
| ConnectionStrings:PostgreSQL | Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres | PostgreSQL 连接字符串 |
| PostgreSql:Host | localhost | PostgreSQL 主机（推荐由 Consul `_shared/prod/infrastructure.json` 提供） |
| PostgreSql:Port | 5432 | PostgreSQL 端口（推荐由 Consul `_shared/prod/infrastructure.json` 提供） |
| PostgreSql:Username | postgres | PostgreSQL 用户名（推荐由 Consul `_shared/prod/infrastructure.json` 提供） |
| PostgreSql:Password | （空） | PostgreSQL 密码（推荐由 Consul `_shared/prod/infrastructure.json` 提供） |

> PostgreSQL 连接字符串自动追加连接池参数：`Pooling=true;Minimum Pool Size=5;Maximum Pool Size=100;Connection Lifetime=300`。如连接字符串中已包含 `Pooling=` 则不追加。

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

> **SMS 发送器选择**：开发环境使用 `LoggingSmsSender`（仅记录日志，验证码掩码显示）；生产环境使用 `ThrowingSmsSender`（调用时抛出异常，防止验证码泄露）。生产环境需配置真实 SMS 提供商实现替换 `ThrowingSmsSender`。

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

## 回调配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Callback:AllowedDomains | [] | 允许的回调域名列表（空=不限制） |

> `CallbackUrlValidator` 构造函数默认 `allowPrivateAddresses = true`（允许私有 IP）。如需禁用（例如公网部署），可通过 `Callback:AllowPrivateAddresses: false` 显式覆盖（`Program.cs` 会读取该键并传入构造函数）。默认允许私有 IP 是微服务内网通信的常态。

## OpenTelemetry 配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| OpenTelemetry:OtlpEndpoint | （空） | OTLP 导出端点（如 `http://localhost:4317`），为空时不启用 OTLP 导出 |

## 运行时配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| HostOptions.ShutdownTimeout | 30 秒 | 优雅关闭超时时间，超时后强制终止请求 |
| Kestrel.RequestHeadersTimeout | 30 秒 | 请求头接收超时 |
| JWKS RateLimiter | 60 次/分钟 | JWKS 端点速率限制 |

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

Identity 服务使用 Serilog 替代原生 Microsoft.Extensions.Logging，双写到 Console + Grafana Loki。业务代码中的 `ILogger<T>` 调用无需修改。

### Serilog 配置

服务实际通过 Serilog 输出日志（`builder.Host.UseAgentSerilog`）。`appsettings.json` 中的 `Logging` 节仅保留给未走 Serilog 的少量运行时组件，**业务日志级别以 Serilog 配置为准**。

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Serilog:MinimumLevel:Default | Information | 默认日志级别 |
| Serilog:MinimumLevel:Override:Microsoft.AspNetCore | Warning | ASP.NET Core 日志级别 |
| Serilog:MinimumLevel:Override:Microsoft.EntityFrameworkCore | Warning | EF Core 日志级别 |
| Serilog:WriteTo:0:Name | Console | 控制台 Sink（数组下标 0） |
| Serilog:WriteTo:1:Name | GrafanaLoki | Loki Sink（数组下标 1） |
| Serilog:WriteTo:1:Args:uri | http://localhost:3100 | Loki 地址（最终由 `Loki:Uri` 覆盖） |
| Serilog:WriteTo:1:Args:labels:0:key | service | Loki 标签键 |
| Serilog:WriteTo:1:Args:labels:0:value | QuantumZhou.Identity | Loki 标签值（service 标签） |

### 日志 Enricher

每条日志自动携带以下字段：

| 字段 | 来源 | 说明 |
|------|------|------|
| ServiceName | UseAgentSerilog 参数 | 固定为 `QuantumZhou.Identity` |
| ServiceVersion | UseAgentSerilog 参数 | 默认 `1.0.0` |
| InstanceId | Environment.MachineName | 实例标识 |
| MachineName | Enrichers.Environment | 主机名 |
| ThreadId | Enrichers.Thread | 线程 ID |

### Loki 地址注入

Loki 地址统一通过 `Loki:Uri` 配置键进入 `Serilog:WriteTo:1:Args:uri`：

| 来源 | 示例值 | 说明 |
|------|--------|------|
| `Loki:Uri` 配置键 | http://ruoyu-loki:3100 | 推荐由 Consul `_shared/prod/infrastructure.json` 提供 |

> **容错机制**：如果 `Loki:Uri` 未设置，Loki Sink 使用 appsettings.json 中的 fallback 地址 `http://localhost:3100`。Loki 不可达时 Sink 异步重试，不影响服务启动。

### 开发环境覆盖

`appsettings.Development.json`（待创建）覆盖以下配置：

| 配置键 | 默认值 | 开发环境值 | 说明 |
|--------|--------|-----------|------|
| Serilog:MinimumLevel:Default | Information | Debug | 开发环境输出更详细日志 |

> Loki 地址、WriteTo Sinks 等其他配置继承自 `appsettings.json`，开发环境无需重复配置。

### 基础设施

Loki 和 Grafana 通过 `script/env-script/04-loki/start.sh` 和 `script/env-script/05-grafana/start.sh` 启动，数据持久化在脚本目录下的 `data/` 文件夹。

| 组件 | 端口 | 说明 |
|------|------|------|
| Loki | 3100 | 日志接收端点 |
| Grafana | 3000 | 可视化面板（admin/admin），Loki 数据源自动配置 |

Loki 单实例部署的 `replication_factor: 1` 等关键配置详见 `script/env-script/04-loki/Configuration.md`。

> 历史：2026-06-27 远程服务器上 Loki 复现过"`/ready` 200 但 push 500 `at least 2 live replicas required`"的问题，根因是 `common.replication_factor` 缺失，已在 Loki 配置中显式设为 1 修复。Loki 不可达时 Serilog GrafanaLoki Sink 异步重试，不影响服务启动。
