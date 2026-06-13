# QuantumZhou.Identity 部署前修改计划

经过对全部代码的仔细审查，发现以下 **必须在部署前修复/处理** 的问题，按严重程度分类。

---

## 🔴 严重问题（会导致构建失败或运行时崩溃）

### 1. Dockerfile 中引用了不存在的 `app` 用户 — 构建必定失败

**文件**: `scripts/1.build/Dockerfile` 第26-28行

```dockerfile
RUN mkdir -p /app/master-key /app/admin-credentials && \
    chown -R app:app /app/master-key /app/admin-credentials && \
    chmod -R 755 /app/master-key /app/admin-credentials
```

`mcr.microsoft.com/dotnet/aspnet:8.0` 基础镜像中不存在 `app` 用户，`chown -R app:app` 会导致 Docker 构建失败。

**修复方案**: 先创建 `app` 用户，再执行 chown：
```dockerfile
RUN adduser --disabled-password --gecos "" app && \
    mkdir -p /app/master-key /app/admin-credentials && \
    chown -R app:app /app/master-key /app/admin-credentials && \
    chmod -R 755 /app/master-key /app/admin-credentials
```
并在 `final` 阶段添加 `USER app` 以非 root 用户运行。

---

### 2. deploy.sh 镜像标签硬编码 — 部署时必定找不到镜像

**文件**: `scripts/2.deploy/deploy.sh` 第9行

```bash
IMAGE_NAME="quantumzhou.identity:20260424"
```

镜像标签硬编码为 `20260424`，而 `build.sh` 使用当前日期动态生成标签。部署时如果日期不匹配，Docker 会找不到镜像。

**修复方案**: 将镜像标签参数化，从环境变量或命令行参数读取，或与 build.sh 共享标签逻辑。

---

### 3. 缺少 EF Core Migrations — 生产数据库无法正确初始化

**问题**: 项目中没有任何 `Migrations` 文件夹。`Program.cs` 的数据库初始化逻辑为：

```csharp
var pendingMigrations = db.Database.GetPendingMigrations();
if (pendingMigrations.Any())
{
    db.Database.Migrate();
}
else
{
    db.Database.EnsureCreated();
}
```

由于没有 Migration 类，`GetPendingMigrations()` 永远返回空，因此总是执行 `EnsureCreated()`。`EnsureCreated()` 在 PostgreSQL 上存在以下问题：
- 如果数据库已存在且由 Migration 创建，`EnsureCreated()` 会跳过，导致新表不创建
- 后续如果添加 Migration，`EnsureCreated()` 和 `Migrate()` 会冲突
- 不支持增量 schema 变更

**修复方案**: 
1. 创建初始 EF Core Migration：`dotnet ef migrations add InitialCreate`
2. 移除 `EnsureCreated()` 回退逻辑，仅保留 `Migrate()`
3. 在 CI/CD 中或部署脚本中执行 `dotnet ef database update`

---

### 4. 缺少发送验证码的 gRPC 接口 — SMS 登录功能不完整

**文件**: `src/Contract/Protos/auth.proto`

当前 proto 只定义了 `GetToken`、`RegisterCallback`、`RevokeRefreshToken` 三个 RPC。`IOtpService.GenerateAndSendAsync()` 方法存在但从未被任何 gRPC 服务调用。这意味着：
- 客户端无法通过 API 请求发送短信验证码
- SMS 登录流程缺少第一步（发送验证码）
- `DbOtpService` 和 `InMemoryOtpService` 的 `GenerateAndSendAsync` 方法是死代码

**修复方案**: 在 `auth.proto` 中添加 `RequestSmsCode` RPC：
```protobuf
rpc RequestSmsCode(RequestSmsCodeRequest) returns (RequestSmsCodeResponse);

message RequestSmsCodeRequest {
  string phone = 1;
}

message RequestSmsCodeResponse {
  bool success = 1;
  string message = 2;
}
```
并在 `AuthServiceImpl` 中实现该方法。

---

## 🟠 高优先级问题（安全风险或功能缺陷）

### 5. LoggingSmsSender 在生产环境记录明文验证码 — 安全漏洞

**文件**: `src/Domain/Services/Sms/LoggingSmsSender.cs` 第16行

```csharp
_logger.LogInformation("[SMS-DEV] Phone={Phone}, Code={Code} — SMS sent (logging only in dev mode)", phone, code);
```

`LoggingSmsSender` 是当前唯一注册的 `ISmsSender` 实现，它将验证码明文写入日志。在生产环境中，任何能访问日志的人都可以获取验证码，绕过 SMS 认证。

**修复方案**: 
- 创建一个真正的 SMS 发送实现（对接阿里云/腾讯云 SMS API）
- 或至少创建一个 `ThrowingSmsSender`，在生产环境调用时抛出异常，防止误用
- 根据环境变量选择实现：开发环境用 `LoggingSmsSender`，生产环境用真实实现

---

### 6. AdminAppOptions 每次容器重启可能重新生成凭据 — 导致所有客户端失效

**文件**: `src/Domain/AdminAppOptions.cs`

`LoadFromEnvironmentOrGenerate()` 在没有设置 `ADMIN_APP_ID` 和 `ADMIN_APP_SECRET` 环境变量时，会生成新的凭据。虽然 `AdminCredentialsGenerator` 会将凭据写入文件，但：

- `deploy.sh` 没有传递 `ADMIN_APP_ID` 和 `ADMIN_APP_SECRET` 环境变量
- 如果 volume 中的 `credentials.json` 文件丢失（如重建容器时），管理员凭据会改变
- 没有任何机制通知管理员新的凭据

**修复方案**: 
1. 在 `deploy.sh` 中添加 `ADMIN_APP_ID` 和 `ADMIN_APP_SECRET` 环境变量传递
2. 在 `AdminAppOptions.LoadFromEnvironmentOrGenerate()` 中增加从文件读取已有凭据的逻辑（当前 `AdminCredentialsGenerator` 有 `ReadCredentials()` 方法但未被调用）

---

### 7. deploy.sh 中数据库密码明文硬编码 — 安全风险

**文件**: `scripts/2.deploy/deploy.sh` 第16-19行

```bash
DB_HOST="10.13.13.5"
DB_PORT="5432"
DB_NAME="ruoyu_identity"
DB_USER="postgres"
DB_PASS="postgres"
```

数据库连接信息（包括密码）直接硬编码在脚本中。

**修复方案**: 从环境变量或 `.env` 文件中读取敏感信息：
```bash
DB_HOST="${DB_HOST:-10.13.13.5}"
DB_PASS="${DB_PASS:?DB_PASS environment variable is required}"
```

---

### 8. JWKS RateLimiter 未随应用生命周期释放 — 资源泄漏

**文件**: `src/Host/Program.cs` 第272-279行

```csharp
var jwksRateLimiter = new System.Threading.RateLimiting.FixedWindowRateLimiter(...);
```

`FixedWindowRateLimiter` 实现了 `IDisposable`，但从未被释放。虽然对运行时影响较小，但在优雅关闭场景下可能导致资源泄漏。

**修复方案**: 注册到 `IHostApplicationLifetime` 的 `ApplicationStopping` 事件中释放，或使用 `app.Lifetime` 注册清理逻辑。

---

## 🟡 中优先级问题（生产环境健壮性）

### 9. 缺少 appsettings.Production.json — 生产配置无差异化

当前只有 `appsettings.json`，没有生产环境专用配置文件。`.gitignore` 中排除了 `appsettings.*.json`，这意味着生产配置需要手动管理。

**修复方案**: 创建 `appsettings.Production.json` 模板，包含：
- 更严格的日志级别（`Microsoft.EntityFrameworkCore` 设为 `Error`）
- 生产环境的 `Database:AutoMigrate` 设为 `false`
- 生产环境的 JWT 配置占位符

---

### 10. OpenTelemetry Tracing 没有配置导出端点 — 链路追踪无效

**文件**: `src/Host/Program.cs` 第37-42行

```csharp
.WithTracing(tracing =>
{
    tracing.AddAspNetCoreInstrumentation()
           .AddHttpClientInstrumentation()
           .AddSource("QuantumZhou.Identity");
});
```

Tracing 配置了采集但没有配置任何导出器（如 OTLP/Jaeger/Zipkin），导致采集的 trace 数据无处发送，完全无效。

**修复方案**: 添加 OTLP 导出器配置：
```csharp
tracing.AddOtlpExporter(options => 
{
    options.Endpoint = new Uri(builder.Configuration["OpenTelemetry:OtlpEndpoint"] ?? "http://localhost:4317");
});
```

---

### 11. PostgreSQL 连接缺少连接池配置 — 生产性能风险

**文件**: `src/Host/Program.cs` 第66-72行

Npgsql 的 `UseNpgsql` 没有配置连接池参数，使用默认值。在高并发场景下，默认连接池可能不够用。

**修复方案**: 在连接字符串中添加池化参数，或在 `UseNpgsql` 中配置：
```
Pooling=true;Minimum Pool Size=5;Maximum Pool Size=100;Connection Lifetime=300;
```

---

### 12. RateLimitingInterceptor 使用 Peer 标识客户端 — 限流不准确

**文件**: `src/Service/RateLimitingInterceptor.cs` 第32行

```csharp
var clientIp = context.Peer;
```

`context.Peer` 的格式为 `ipv4:127.0.0.1:12345`，包含端口号。这意味着同一客户端的不同连接会被视为不同的限流对象，限流效果大打折扣。

**修复方案**: 从 `Peer` 中提取纯 IP 地址：
```csharp
var peer = context.Peer;
var clientIp = peer.StartsWith("ipv4:") ? peer.Split(':')[1] : peer;
```

---

### 13. Dockerfile 中 ASPNETCORE_URLS 与实际监听端口不一致 — 混淆

**文件**: `scripts/1.build/Dockerfile` 第6行

```dockerfile
ENV ASPNETCORE_URLS=http://+:5001
```

`Program.cs` 中通过 `ConfigureKestrel` 显式配置了 5001 和 5002 两个端口，`ASPNETCORE_URLS` 环境变量会被覆盖。但保留这个环境变量会造成混淆，让人误以为只监听 5001。

**修复方案**: 移除 `ENV ASPNETCORE_URLS` 行，因为 Kestrel 配置已经处理了端口监听。

---

### 14. SQLite 数据库文件存在于源码树 — 不应被追踪

**文件**: `src/Host/quantumzhou_identity.db`

SQLite 数据库文件存在于源码目录中，不应被版本控制追踪。

**修复方案**: 将 `*.db` 添加到 `.gitignore`，并删除该文件。

---

### 15. CallbackUrlValidator 的 DNS 解析可能造成延迟或 SSRF

**文件**: `src/Domain/Services/CallbackUrlValidator.cs` 第48-66行

`IsPrivateIpAddress` 方法对域名执行 `Dns.GetHostAddresses()` 同步 DNS 解析，可能导致：
- 请求处理线程阻塞（DNS 解析可能耗时数秒）
- DNS 重绑定攻击绕过 SSRF 防护

**修复方案**: 
- 使用异步 DNS 解析
- 考虑缓存 DNS 结果
- 或在生产环境中使用白名单模式替代黑名单

---

## 🔵 低优先级建议（改善运维体验）

### 16. 缺少 docker-compose.yml — 部署编排不便

当前只有独立的 `build.sh` 和 `deploy.sh`，缺少 docker-compose 配置来编排 Identity 服务和 PostgreSQL。

**修复方案**: 创建 `docker-compose.yml`，包含 Identity 服务和 PostgreSQL 服务。

---

### 17. 缺少 graceful shutdown 处理 — 长连接请求可能被中断

`Program.cs` 中注册了 `ApplicationStopping` 日志，但没有配置请求排空（drain）逻辑。在 Kubernetes 环境中，Pod 终止时正在处理的 gRPC 请求可能被强制中断。

**修复方案**: 配置 Kestrel 的 shutdown timeout：
```csharp
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
    options.ShutdownTimeout = TimeSpan.FromSeconds(30);
});
```

---

### 18. OtpService 注册逻辑有误导性

**文件**: `src/Host/Program.cs` 第128-135行

```csharp
if (!string.IsNullOrWhiteSpace(connectionString))
{
    builder.Services.AddScoped<IOtpService, DbOtpService>();
}
else
{
    builder.Services.AddSingleton<IOtpService, InMemoryOtpService>();
}
```

`connectionString` 几乎永远不为空（有默认值回退），所以 `InMemoryOtpService` 实际上永远不会被使用。条件判断逻辑与意图不符。

**修复方案**: 改为根据数据库提供者类型决定：
```csharp
if (dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddScoped<IOtpService, DbOtpService>();
}
else
{
    builder.Services.AddSingleton<IOtpService, InMemoryOtpService>();
}
```

---

## 执行顺序

| 步骤 | 修改项 | 优先级 |
|------|--------|--------|
| 1 | 修复 Dockerfile 用户问题 (#1) | 🔴 严重 |
| 2 | 修复 deploy.sh 镜像标签 (#2) | 🔴 严重 |
| 3 | 创建 EF Core Migrations (#3) | 🔴 严重 |
| 4 | 添加 RequestSmsCode gRPC 接口 (#4) | 🔴 严重 |
| 5 | 修复 SMS 发送器安全问题 (#5) | 🟠 高 |
| 6 | 修复 AdminAppOptions 凭据持久化 (#6) | 🟠 高 |
| 7 | 修复 deploy.sh 密码硬编码 (#7) | 🟠 高 |
| 8 | 修复 JWKS RateLimiter 泄漏 (#8) | 🟠 高 |
| 9 | 添加 appsettings.Production.json (#9) | 🟡 中 |
| 10 | 配置 OpenTelemetry OTLP 导出 (#10) | 🟡 中 |
| 11 | 配置 PostgreSQL 连接池 (#11) | 🟡 中 |
| 12 | 修复 RateLimiting IP 提取 (#12) | 🟡 中 |
| 13 | 移除 Dockerfile 多余 ENV (#13) | 🟡 中 |
| 14 | 清理 SQLite 文件和 .gitignore (#14) | 🟡 中 |
| 15 | 修复 CallbackUrlValidator DNS 问题 (#15) | 🟡 中 |
| 16 | 创建 docker-compose.yml (#16) | 🔵 低 |
| 17 | 添加 graceful shutdown (#17) | 🔵 低 |
| 18 | 修复 OtpService 注册逻辑 (#18) | 🔵 低 |
