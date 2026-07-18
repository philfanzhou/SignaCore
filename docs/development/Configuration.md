# 配置参考 (Configuration)

> 本文档列出所有配置项及其来源。
>
> **当前部署脚本优先级**：命令行 > 环境变量 > Consul KV（`config/ruoyu/*`）> 本地缓存 > appsettings.{Env} > appsettings.json
>
> 详见 [ConsulIntegration.md](./ConsulIntegration.md)

## Consul 集成配置

| 配置键 | 环境变量 | 默认值 | 说明 |
|--------|---------|--------|------|
| `Consul:Host` / `Consul:Port` | `CONSUL_HTTP_ADDR` | `host.docker.internal:8500` | 部署侧统一传一个地址字符串，运行时拆成 Host / Port |
| `Consul:ServiceName` | `CONSUL_SERVICE_NAME` | `QuantumZhou.Identity` | 注册到 Consul 的服务名称；通常使用应用默认值即可 |
| `Consul:ServiceId` | `CONSUL_SERVICE_ID` | 自动生成 | 服务实例 ID（多实例需唯一）|
| `Consul:KvPrefix` | `CONSUL_KV_PREFIX` | `config/ruoyu` | KV 路径前缀 |
| `Consul:TimeoutMs` | `CONSUL_TIMEOUT_MS` | `3000` | 单次请求超时（毫秒） |
| `Consul:RetryCount` | `CONSUL_RETRY_COUNT` | `3` | 连接重试次数（指数退避） |
| `Consul:EnableCache` | `CONSUL_ENABLE_CACHE` | `true` | 是否启用本地缓存兜底 |
| `Consul:Token` | `CONSUL_TOKEN` | （空） | Consul ACL token（启用 ACL 时必需） |

> Consul 配置的详细语义、启动时序、缓存机制、KV 分层策略请见 [ConsulIntegration.md](./ConsulIntegration.md)。
>
> **当前约束**：Consul 只承载跨项目共享配置。Identity 启动脚本不再注入数据库主机、端口、用户名、密码和 Loki 地址；`Database:Provider` 使用程序默认值，`Database:Name`、`FeatureFlags` 这类项目独有配置保留在服务自身配置中。`RSA_MASTER_KEY`、管理员引导密码、AppSecret 等启动密钥仍保留在环境变量或文件。
>
> **启动诊断日志**：服务启动时会输出 Consul 拉取过程和最终生效配置摘要。`CONSUL_TOKEN`、数据库密码等敏感值只打印脱敏摘要，不打印完整明文。

---

## 端口配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Endpoints:Http | 5002 | HTTP 监听端口（业务/认证，HTTP/1.1 + HTTP/2） |

## 数据库配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Database:Provider | PostgreSQL | 数据库提供者（默认由项目配置提供，通常无需 `start.sh` 重复注入） |
| Database:Name | quantumzhou_identity | 服务自己的 PostgreSQL 数据库名（可按需由项目 `start.sh` 覆盖） |
| ConnectionStrings:Default | Data Source=quantumzhou_identity.db | SQLite 连接字符串 |
| ConnectionStrings:PostgreSQL | Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres | PostgreSQL 连接字符串 |
| PostgreSql:Host | localhost | PostgreSQL 主机（推荐由 Consul `config/ruoyu/shared.json` 提供） |
| PostgreSql:Port | 5432 | PostgreSQL 端口（推荐由 Consul `config/ruoyu/shared.json` 提供） |
| PostgreSql:Username | postgres | PostgreSQL 用户名（推荐由 Consul `config/ruoyu/shared.json` 提供） |
| PostgreSql:Password | （空） | PostgreSQL 密码（推荐由 Consul `config/ruoyu/shared.json` 提供） |

> PostgreSQL 连接字符串自动追加连接池参数：`Pooling=true;Minimum Pool Size=5;Maximum Pool Size=100;Connection Lifetime=300`。如连接字符串中已包含 `Pooling=` 则不追加。
>
> **数据库自动创建**：PostgreSQL 模式下，服务启动时会先用维护连接（连接到 `postgres` 维护数据库）检查目标数据库是否存在；不存在则自动执行 `CREATE DATABASE`。该机制保证 `start.sh` 只需提供 `Database:Name`，无需人工预建数据库。SQLite 模式下由 `EnsureCreated()` 直接创建库表。
>
> **排查建议**：如果启动日志仍显示 `PostgreSql:Host=localhost`，优先检查 Consul 拉取日志中的来源字段是否已回退到 `Cache` 或 `AppSettings`，以及 `CONSUL_TOKEN` 是否被识别为有效输入。

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

## 功能开关

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| FeatureFlags:EnableNewLogin | true | Identity 新登录流程开关，项目自有配置，不走 Consul |
| FeatureFlags:EnablePeriodicCheckIn | true | Identity 定时签到相关开关，项目自有配置，不走 Consul |

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
| AdminWeb:AdminUsernames | [] | 允许访问管理端的用户名白名单（空=允许所有，`start.sh` 不再重复注入默认管理员） |
| AdminWeb:AllowedOrigins | ["http://localhost:5173"] | CORS 允许的前端来源 |
| AdminBootstrap:Username | admin | 初始管理员用户名。该账号在密码登录时**无条件**获得 `role:admin`（绕过 callback），无论从哪个 portal 登录 |
| AdminBootstrap:Password | （空） | 初始管理员密码（生产环境必须通过环境变量配置） |
| ADMIN_BOOTSTRAP_USERNAME（环境变量） | - | 初始管理员用户名，优先级高于配置文件 |
| ADMIN_BOOTSTRAP_PASSWORD（环境变量） | - | 初始管理员密码，优先级高于配置文件 |

> **Bootstrap Admin 角色注入**：密码登录时，若 `request.Username` 与 `AdminBootstrap:Username` 相等（`StringComparison.OrdinalIgnoreCase`，且配置非空），Identity 在签发 JWT 前无条件注入 `role=admin`。注入前检查是否已存在该角色，避免重复。SMS/微信登录不触发。这是"超级管理员"账号，**无需配置 admin_portal 的 `AdminUserIds` 白名单**即可获得 admin 角色。

## Bootstrap Apps 配置

Identity 启动时通过挂载的 `data/bootstrap-apps.json` 文件预置应用注册信息。该机制用于首次部署时预置基础应用（如 Teacher Portal、Admin Portal 的应用凭据），运行时动态管理仍通过 Admin API (`POST /api/admin/apps`) 完成。

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| BootstrapApps:FilePath | /app/data/bootstrap-apps.json | 应用预置文件路径（容器内绝对路径） |

**文件格式**（JSON 对象，顶层 `apps` 数组）：

```json
{
  "apps": [
    {
      "appId": "a6eab9bd87404c0ababc910114d11a62",
      "appSecret": "cGzoAwXaP+PahtDqXYVY75IJiPWtfbt/4SIt+WrKoQ=",
      "appName": "Teacher Portal",
      "callbackUrl": "http://ruoyu-teacher-api:5004/api/auth/callback"
    }
  ]
}
```

**字段说明**：

| 字段 | 必填 | 说明 |
|------|------|------|
| appId | 是 | 应用唯一标识（32 位十六进制，由 Admin API 创建时生成，预置时需人工指定） |
| appSecret | 是 | 应用密钥明文（BCrypt 哈希后存储，明文不入库） |
| appName | 是 | 应用显示名称 |
| callbackUrl | 否 | 回调 URL（默认空，注册后可按需通过 Admin API 配置） |

**加载机制**：

- 文件由 `start.sh` 通过 `-v` 挂载到容器内 `BootstrapApps:FilePath` 指定路径（默认 `/app/data/bootstrap-apps.json`），挂载为只读（`:ro`）
- `DatabaseInitializer` 在迁移完成后读取该文件，若 AppId 已存在则跳过（保持幂等）
- 文件不存在时输出 INFO 日志（该预置机制为可选，不影响服务启动）
- `appSecret` 支持 Base64 字符（含 `+`、`/`、`=`），JSON 字符串原生支持无需转义

**与 Admin API 注册应用的差异**：

| 维度 | Bootstrap Apps 文件预置 | Admin API 动态注册 |
|------|------------------------|-------------------|
| 使用场景 | 首次部署预置基础应用 | 运行时动态管理 |
| 调用时机 | `DatabaseInitializer` 启动时一次性加载 | 管理员随时调用 |
| AppId 生成 | 预置时人工指定（固定值） | `Guid.NewGuid().ToString("N")` |
| AppSecret 来源 | 预置时人工指定 | 服务端生成 32 字节密码学安全随机 |
| 文件不存在 | 正常启动，不预置任何应用 | 不适用 |

> **生产环境建议**：通过 Admin API 动态注册应用（AppSecret 仅在创建时返回一次），避免明文 AppSecret 出现在文件中。如使用文件预置，部署脚本应设置 `chmod 600` 限制文件权限。

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
| `Loki:Uri` 配置键 | http://ruoyu-loki:3100 | 推荐由 Consul `config/ruoyu/shared.json` 提供 |

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
