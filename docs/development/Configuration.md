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
| Database:AutoMigrate | true | 是否自动执行迁移（生产环境建议设为 false） |
| ConnectionStrings:Default | Data Source=quantumzhou_identity.db | SQLite 连接字符串 |
| ConnectionStrings:PostgreSQL | Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres | PostgreSQL 连接字符串 |
| DB_PASSWORD（环境变量） | - | PostgreSQL 密码，自动追加到连接字符串 |

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

## gRPC 配置

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Grpc:MaxReceiveMessageSize | 4194304 | 最大接收消息大小（4MB） |
| Grpc:MaxSendMessageSize | 4194304 | 最大发送消息大小（4MB） |

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

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| Serilog:MinimumLevel:Default | Information | 默认日志级别 |
| Serilog:MinimumLevel:Override:Microsoft.AspNetCore | Warning | ASP.NET Core 日志级别 |
| Serilog:MinimumLevel:Override:Microsoft.EntityFrameworkCore | Warning | EF Core 日志级别 |
| Serilog:MinimumLevel:Override:Grpc | Warning | gRPC 日志级别 |
| Serilog:WriteTo:0:Name | Console | 控制台 Sink（数组下标 0） |
| Serilog:WriteTo:1:Name | GrafanaLoki | Loki Sink（数组下标 1） |
| Serilog:WriteTo:1:Args:uri | http://localhost:3100 | Loki 地址（fallback 默认值，生产环境必须通过环境变量覆盖） |
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

Loki 地址通过短环境变量 `LOKI_URI` 注入，Program.cs 启动时读取并覆盖 `Serilog:WriteTo:1:Args:uri` 配置键：

| 环境变量 | 示例值 | 说明 |
|----------|--------|------|
| LOKI_URI | http://loki.example.com:3100 | Loki 地址（生产环境必须设置） |

> **容错机制**：如果 `LOKI_URI` 未设置，Loki Sink 使用 appsettings.json 中的 fallback 地址 `http://localhost:3100`。Loki 不可达时 Sink 异步重试，不影响服务启动。启动时检测到 `LOKI_URI` 未设置会输出警告日志，但不会阻止服务启动。

### 开发环境覆盖

`appsettings.Development.json` 覆盖以下配置：

| 配置键 | 默认值 | 开发环境值 | 说明 |
|--------|--------|-----------|------|
| Serilog:MinimumLevel:Default | Information | Debug | 开发环境输出更详细日志 |
| Serilog:MinimumLevel:Override:Grpc | Warning | Information | 开发环境输出 gRPC 详细日志 |

> Loki 地址、WriteTo Sinks 等其他配置继承自 `appsettings.json`，开发环境无需重复配置。

### 基础设施

Loki 和 Grafana 通过 `script/env-script/04-loki/start.sh` 和 `script/env-script/05-grafana/start.sh` 启动，数据持久化在脚本目录下的 `data/` 文件夹。

| 组件 | 端口 | 说明 |
|------|------|------|
| Loki | 3100 | 日志接收端点 |
| Grafana | 3000 | 可视化面板（admin/admin），Loki 数据源自动配置 |

Loki 单实例部署的 `replication_factor: 1` 等关键配置详见 `script/env-script/04-loki/Configuration.md`。

### 启动连通性探活（Loki）

服务启动时会异步探测 Loki 可达性，**仅记录警告，不阻塞启动**。两阶段检查：

#### 阶段 1：进程级（HTTP `/ready`）

- **做什么**：对 `LOKI_URI` 发起 `GET /ready` 请求
- **能发现什么**：Loki 进程是否监听端口、容器是否启动
- **不能发现什么**：distributor 写入路径是否可用、querier 查询路径是否可用、ring 副本数是否满足
- **失败行为**：记录 `WARN` 日志 `Loki connectivity check failed: ... is not reachable`

#### 阶段 2：业务级（push smoke test）

- **做什么**：向 `LOKI_URI/loki/api/v1/push` 推送一条最小样本（`{service=QuantumZhou.Identity.smoketest}`）
- **能发现什么**：distributor 副本数、ingester 副本数、push API 端到端可达
- **不能发现什么**：querier 查询路径（labels/series）的问题——这需要单独验证，参见 `Verification.md` 的 "Loki smoke test 验证"
- **失败行为**：记录 `WARN` 日志 `Loki push smoke test failed: ...`，并附 HTTP 状态码与响应体（便于排查 `at least N live replicas required` 等 Loki 内部错误）
- **不阻塞启动**：业务进程已经能产生日志，推送失败只意味着日志进不去 Loki，不影响对外服务

> **设计动机**：仅靠 `/ready` 探活会漏掉"进程在但服务不可用"的故障（例如 Loki 单实例部署忘了配 `replication_factor: 1`，导致 push 持续 500 但 `/ready` 仍返回 200）。push smoke test 是"以真实路径发一单"的最轻量业务级验证。
>
> 历史背景：2026-06-27 远程服务器 192.168.55.2 上的 Loki 复现了上述问题——`/ready` 200、push 500 `at least 2 live replicas required, could only find 1`、labels 持续超时。该 commit 同步修复了 Loki 配置和探活策略。

#### 探活失败排查清单

| 现象 | 可能原因 | 处置 |
|------|----------|------|
| `/ready` 不可达 | Loki 容器未启动 / 端口未暴露 / 防火墙阻断 / `LOKI_URI` 写错 | 检查 `docker ps`、`docker logs ruoyu-loki`、主机端口、URL |
| `/ready` 200 但 push 500 | `replication_factor` 缺失（单实例必须设为 1） | 改 `loki-config.yaml` 加 `common.replication_factor: 1` 并重启 Loki |
| push 200 但 labels 超时 | ingester ring 健康副本数不足 / 单实例下 querier 配置异常 | 检查 `/services`、`/ring` 端点状态 |
| `LOKI_URI` 未设置告警 | 启动时未注入环境变量 | 检查 `start.sh` 中 `LOKI_URI=...` 行，容器内 `docker exec ... env | grep LOKI` |
