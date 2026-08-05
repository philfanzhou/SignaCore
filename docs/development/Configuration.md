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
> **当前约束**：容器部署的数据库配置由 Consul `config/ruoyu/identity.json` 提供，使用 `Database:Provider`、`Database:ServerVersion` 和 `Database:ConnectionString`。环境变量 `Database__*` 仅用于显式覆盖；Consul 共享快照中的旧 `PostgreSql:*` 键会被 Identity 过滤，不参与数据库配置。`RSA_MASTER_KEY`、管理员引导密码、AppSecret 等启动密钥仍保留在环境变量或文件。
>
> **启动诊断日志**：服务启动时会输出 Consul 拉取过程和最终生效配置摘要。`CONSUL_TOKEN`、数据库密码等敏感值只打印脱敏摘要，不打印完整明文。

---

## 端口配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Endpoints:Http | 5002 | HTTP 监听端口（业务/认证，仅 HTTP/1.1，见 Program.cs `listenOptions.Protocols = HttpProtocols.Http1`） |

> 历史键 `Endpoints:AdminApi` 从未被代码读取（死配置），已于 2026-07-22 从 appsettings.json 移除。

## 管理前端标题（APP_TITLE）

管理控制台（admin_frontend）的浏览器 tab 标题与页面内标题（侧边栏 brand、登录页副标题）统一来自运行时注入的 `APP_TITLE`，同一镜像可适配不同项目部署：

| 配置键 | 环境变量 | 默认值 | 说明 |
|--------|---------|--------|------|
| APP_TITLE | `APP_TITLE` | `QuantumZhou.Identity` | 管理控制台标题；`start.sh` 传 `-e APP_TITLE="${CONTAINER_NAME}"` |

**注入机制**（Program.cs "Static files & SPA for Admin Web" 段）：

- 仅在 HTTP 端口且非 `/api`、`/.well-known`、`/health`、`/metrics` 路径下生效（SPA 静态托管分支）
- 请求 `/index.html` 时：将文件中 `<title>__APP_TITLE__</title>` 占位符替换为 `APP_TITLE` 值（浏览器 tab 标题），并向 `</head>` 前注入 `<script>window.__APP_TITLE__ = '...'</script>` 全局变量（`'` 转义为 `\'`）
- 前端以 `window.__APP_TITLE__ || 'QuantumZhou.Identity'` 读取（vite dev 直出时走后端代理或取兜底值），页面内标题与 tab 标题同源
- `index.html` 中的 `__APP_TITLE__` 占位符**不得**替换为硬编码文案，否则运行时注入失效

## 数据库配置

| 配置键 | 环境变量 | 要求 |
|--------|---------|------|
| `Database:Provider` | `Database__Provider` | 必填；只允许 `PostgreSQL`、`MySQL`、`MariaDB`、`SQLite` |
| `Database:ServerVersion` | `Database__ServerVersion` | PostgreSQL、MySQL、MariaDB 必填；SQLite 禁止配置 |
| `Database:ConnectionString` | `Database__ConnectionString` | 必填；唯一连接字符串入口 |

支持矩阵：

| Provider | 支持版本 | 部署边界 |
|----------|----------|----------|
| PostgreSQL | 15+ | 默认选择，支持单实例和多实例 |
| MySQL | 8.0、8.4 | 支持单实例和多实例 |
| MariaDB | 10.11、11.4 | 支持单实例和多实例 |
| SQLite | 随 EF Core provider 交付 | 仅限单实例、本地磁盘文件 |

SQLite 示例：

```json
{
  "Database": {
    "Provider": "SQLite",
    "ConnectionString": "Data Source=/app/data/identity.db"
  }
}
```

旧键 `PostgreSql:*`、`ConnectionStrings:Default`、`ConnectionStrings:PostgreSQL` 和 `Database:Name` 不再受支持。它们出现在本地配置或环境变量时会阻止启动；Consul 共享快照中的旧键会在进入 Identity 配置前过滤。

服务会自动创建目标数据库并执行迁移。PostgreSQL 使用 advisory lock，MySQL/MariaDB 使用 `GET_LOCK` 串行化多实例迁移；SQLite 依赖单实例部署契约。完整连接字符串和密码不会写入日志。

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

Identity 没有功能开关配置。

> 历史键 `FeatureFlags:EnableNewLogin`、`FeatureFlags:EnablePeriodicCheckIn` 从未被代码读取（单体导入时遗留的死配置，签到属于业务侧而非本上下文），已于 2026-08-01 从 appsettings.json 移除。

## 密码哈希配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| PasswordHasher:WorkFactor | 11 | BCrypt WorkFactor（越高越安全，越慢）。默认值取自 `IdentityConstants.BCryptWorkFactor` |

## 短信 OTP 配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Sms:OtpTtlSeconds | 300 | 验证码有效期（秒） |
| Sms:MaxAttempts | 5 | 最大验证尝试次数 |
| Sms:LockoutSeconds | 600 | 超过最大尝试后锁定时间（秒） |
| Sms:BypassCode | （空） | 绕过验证码，空值=禁用 |
| Sms:BypassPhones | （空） | 允许使用绕过码的手机号白名单，空=绕过整体禁用 |
| SMS_BYPASS_CODE（环境变量） | - | 绕过验证码，配置文件缺失时回退到该变量 |
| SMS_BYPASS_PHONES（环境变量） | - | 绕过白名单，逗号分隔，配置文件缺失时回退到该变量 |

> **绕过码必须配合白名单**：`Sms:BypassCode` 单独配置不生效——`BypassPhones` 为空时 `SmsValidator` 不放行任何号码。
> 白名单在 Consul KV 里写 JSON 数组，在环境变量里写逗号分隔字符串，两种形式都支持：
>
> ```jsonc
> // config/ruoyu/identity.json
> "Sms": { "BypassPhones": ["13800138000"] }
> ```
>
> ```bash
> SMS_BYPASS_PHONES=13800138000,13900139000
> ```
>
> 绕过路径**不经过** OTP 校验，因此 `MaxAttempts` / `LockoutSeconds` 对它无效。白名单是唯一的收口手段，
> 名单里只能放测试号码，绝不能放真实用户号码。命中绕过时会打一条 Warning 日志（手机号已掩码）。
>
> **优先级陷阱**：`ProgramConsulExtensions.ApplySnapshotWithExpectedPrecedence` 把环境变量源在 Consul 快照之后重放，
> 即环境变量覆盖 Consul。若想改用 Consul KV 管理这两项，必须先把 `start.sh` 里对应的 `-e` 行删掉——
> 否则空环境变量会静默覆盖 Consul 的值，表现为「短信登录失效但日志无提示」。

> **SMS 发送器选择**：开发环境使用 `LoggingSmsSender`（仅记录日志，验证码掩码显示）；生产环境使用 `ThrowingSmsSender`（调用时抛出异常，防止验证码泄露）。生产环境需配置真实 SMS 提供商实现替换 `ThrowingSmsSender`。

## 微信配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| WeChat:AppId | （空） | 微信开放平台 AppId |
| WeChat:AppSecret | （空） | 微信开放平台 AppSecret |
| WeChat:ApiBaseUrl | https://api.weixin.qq.com | 微信 API 基地址 |

## 速率限制配置

限流在代码中硬编码（`ServiceCollectionExtensions.cs` "Rate Limiting" 段），**无配置键**，调整需改代码：

| 项 | 值 | 说明 |
|----|----|----|
| 全局限流 | 100 次 / 60 秒 / 客户端 IP | 固定窗口 + AutoReplenishment；超限返回 429 JSON（`{"status":429,"title":"Too Many Requests",...}`） |
| 豁免路径 | `/health`、`/metrics`、`/.well-known/jwks` | 基础设施端点不进入全局限流 |
| JWKS 端点独立限流 | 60 次 / 60 秒（Program.cs FixedWindowRateLimiter） | 见下文"运行时配置" |

## 回调配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Callback:AllowedDomains | [] | 允许的回调域名列表（空=不限制） |
| Callback:AllowPrivateAddresses | true | 是否允许回调 URL 指向或解析到私有/内网 IP |

> 默认允许私有 IP 是微服务内网通信的常态。公网部署可设为 `false`，此时 `CallbackUrlValidator` 会拒绝主机为私有 IP、或 DNS 解析到私有 IP 的回调 URL（10/172.16-31/192.168/127/0/169.254 网段与 IPv6 link-local、site-local）。该键由 `ServiceCollectionExtensions.AddIdentityInfrastructure` 读取并传入构造函数。

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
| AdminWeb:AllowedOrigins | ["http://localhost:5173"] | CORS 允许的前端来源 |
| AdminBootstrap:Username | admin | 初始管理员用户名，也是**登录 admin_frontend 的唯一账号**。启动时由 `DatabaseInitializer` 在数据库创建该账号 |
| AdminBootstrap:Password | （空） | 初始管理员密码（生产环境必须通过环境变量配置，禁止留空） |
| ADMIN_BOOTSTRAP_USERNAME（环境变量） | - | 初始管理员用户名，优先级高于配置文件 |
| ADMIN_BOOTSTRAP_PASSWORD（环境变量） | - | 初始管理员密码，优先级高于配置文件 |

> **管理员唯一真相源**：管理员身份由 `AdminBootstrap:Username` 单一来源决定，不再维护独立白名单。具体规则：
> - **admin_frontend 登录**：密码校验通过后，账号用户名必须等于 `AdminBootstrapOptions.Username`（`StringComparison.OrdinalIgnoreCase`），否则 403。配置为空时**拒绝所有人**（fail-closed，不再默认放行）。
> - **角色注入**：
>   - **password grant**：若 `request.Username == AdminBootstrap:Username`（且配置非空），Identity 在签发 JWT 前无条件注入 `role=admin`；注入前检查是否已存在该角色，避免重复。
>   - **refresh_token grant**：使用 RefreshTokenValidator 已验证出的 `AccountEntity.Id` 与 `AdminBootstrap:Username` 对应的密码账户 ID 比较；相等则注入 `role=admin`。**不**读取 refresh 请求体中的 `username`，普通账户无法通过伪造 `username=admin` 提权。这保证 bootstrap admin 刷新 Access Token 后仍保留管理员角色。
>   - **sms/wechat_code grant**：不触发 bootstrap admin 注入。
> - 不再支持通过白名单"追加"管理员账号；维护 admin 权限 = 维护 `AdminBootstrap:Username` 这一处配置。

## Bootstrap Apps 配置

Identity 启动时通过 `data/bootstrap-apps.json` 文件预置应用注册信息。该文件位于 `data/` 目录下，随整个 `data/` 目录一并由 `start.sh` 挂载到容器 `/app/data`。该机制用于首次部署时预置基础应用（如 Teacher Portal、Admin Portal 的应用凭据），运行时动态管理仍通过 Admin API (`POST /api/admin/apps`) 完成。

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| BootstrapApps:FilePath | /app/data/bootstrap-apps.json | 应用预置文件路径（容器内绝对路径） |

**文件格式**（JSON 对象，顶层 `apps` 数组）：

```json
{
  "apps": [
    {
      "appId": "<32 位十六进制 AppId>",
      "appSecret": "<AppSecret 明文，从密钥库注入>",
      "appName": "Teacher Portal",
      "callbackUrl": "http://ruoyu-teacher-api:5004/api/auth/callback"
    }
  ]
}
```

> 本仓库是 public repo，**不要在文档或脚本里写真实的 AppId / AppSecret**。
> `bootstrap-apps.json` 由部署脚本从 CI 密钥库生成，不进仓库。

**字段说明**：

| 字段 | 必填 | 说明 |
|------|------|------|
| appId | 是 | 应用唯一标识（32 位十六进制，由 Admin API 创建时生成，预置时需人工指定） |
| appSecret | 是 | 应用密钥明文（BCrypt 哈希后存储，明文不入库） |
| appName | 是 | 应用显示名称 |
| callbackUrl | 否 | 回调 URL（默认空，注册后可按需通过 Admin API 配置） |

**加载机制**：

- 文件由 `start.sh` 通过 `-v "${DATA_DIR}:/app/data"` 挂载到容器内 `BootstrapApps:FilePath` 指定路径（默认 `/app/data/bootstrap-apps.json`）；部署脚本需在启动容器前将 `bootstrap-apps.json` 写入 `data/` 目录
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
| 文件 `data/master-key/master-key.json` | 中 | 本地文件，格式 `{"Key":"base64..."}`，`master-key/` 子目录由 KeyManager 在写入前自动创建（若不存在） |
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
