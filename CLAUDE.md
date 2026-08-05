# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

QuantumZhou.Identity 是统一身份与鉴权微服务（.NET 8 + ASP.NET Core），负责集中认证并签发 RS256 JWT；业务微服务只通过 `/.well-known/jwks` 拉公钥本地校验，不引用本仓库任何程序集。仓库文档、注释与提交信息以中文为主。

## 常用命令

```bash
# 运行（默认 HTTP 5002，Admin API / 管理控制台 SPA 复用同一端口）
cd backend/Host && dotnet run

# 构建镜像（多阶段：Vue 前端 → dotnet publish；构建上下文是仓库根）
bash build.sh

# 部署（停旧容器 → 起新容器，不阻塞；需先 export 凭据环境变量，见 docs/development/Deployment.md）
bash start.sh

# 单元测试
dotnet test backend/Tests/unit/QuantumZhou.Identity.Tests.csproj

# 跑单个测试
dotnet test backend/Tests/unit/QuantumZhou.Identity.Tests.csproj --filter 'FullyQualifiedName~KeyManagerTests'

# 数据库契约测试矩阵（PostgreSQL/MySQL/MariaDB via Testcontainers + 文件 SQLite），默认跳过
RUN_IDENTITY_DATABASE_CONTRACTS=true \
dotnet test backend/Tests/integration/QuantumZhou.Identity.IntegrationTests.csproj \
  --filter 'FullyQualifiedName~DatabaseContractTests'

# 管理前端
cd admin_frontend && npm install && npm run dev   # :5173，代理到 :5002
```

CI（`.github/workflows/ci.yml`，唯一流水线）**只做构建与测试，不做部署**：`build-test`（构建镜像 → 单元测试 → HTTP 端点契约测试 → 真容器冒烟，~2 分钟）→ `database-contracts`（四库契约矩阵，~80 秒），两个 job 都跑 GitHub 托管 runner。发布由人工在部署机上执行（`build.sh` → `start.sh` → 冒烟），见 `docs/development/Deployment.md`。托管 runner 跑 Testcontainers 必须保留 `TESTCONTAINERS_RYUK_DISABLED=true` 与 `--blame-hang`，否则任何卡死都表现为整个 job 静默到超时。

`build-test` 尾部的冒烟起真容器 + 真 PostgreSQL 15，黑盒断言 JWKS、token 失败契约、SPA 标题注入、`/metrics`、`__EFMigrationsHistory`，以及**签发链路端到端**（`password` grant 换 token → 用 JWKS 公钥验回签名，即下游微服务实际走的路径，脚本见 `.github/scripts/verify_jwt.py`，只用标准库实现 RSA 验签）。这些覆盖的是进程内宿主测试够不到的运行时层（镜像 `wwwroot`、entrypoint、完整启动序列下的迁移链）。签出的 token 一律用**标准短名** claim（`sub` / `name` / `role` / `nickname` / `auth_method` / `jti` / `iat`），常量在 `IdentityConstants.Claim*`。**不要在签发路径上写 `ClaimTypes.*`**：`JwtTokenService` 直接构造 `JwtPayload`，不走 `JwtSecurityTokenHandler.CreateToken`，出站短名映射不会发生——claim 写成什么，token 里就是什么，长 URI 会直接漏给非 .NET 下游。冒烟里有护栏：token 中出现 `http://schemas.` 开头的 claim 名即 CI 失败。消费侧（`ProfileController` 等）读 `ClaimTypes.NameIdentifier` 是对的，`MapInboundClaims` 默认开着会把 `sub` 映射回去，这条自消费链路冒烟也会真调一次 `/api/profile/me` 验证。它复用同一个 job 里已构建好的镜像——**新开 job 拿不到这个镜像**，只能重跑 `build.sh` 或走 artifact，两者都更慢。冒烟用的凭据一律在 job 内 `openssl rand` 现生成并 `::add-mask::`，不进 secrets；`ADMIN_BOOTSTRAP_PASSWORD` 必须满足 `DefaultPasswordPolicy`（≥8 位 + 大写 + 小写 + 数字），纯 hex 随机串会让容器在 bootstrap admin 处启动失败。测试里的非 ASCII 字面量一律用转义写法（`\u00C9` 而非 `É`）——曾有字面量被误按 GBK 解码再存回 UTF-8，`CAFÉ` 变成汉字 `CAF脡`，让契约矩阵长期失败。

**本仓库是 public repo**：凭据（管理员密码、短信绕过码与白名单、AppSecret）一律不写进脚本或文档，发布时由部署机上的环境变量注入；workflow 日志全网可读，任何步骤都不得回显 token、密码或响应体。**不要往 CI 里加 self-hosted runner 的 job**——public 仓库下 fork PR 能改 workflow，等于给了陌生人在部署机上执行代码的入口；部署留在人工侧就是为了不存在这个入口。

## 架构要点

### 项目分层

`Host`（ASP.NET Core 宿主、Controllers、中间件、启动初始化）→ `Domain`（validators、KeyManager、TokenService、各类 Service）→ `Database`（EF Core 实体 / DbContext / 仓储 / PostgreSQL 迁移链）。`Database.Migrations.MySql` 与 `Database.Migrations.Sqlite` 只装迁移。`backend/Service` 是空壳项目（只有 csproj，无源码），不要往里加东西。

`Host` 对两个测试程序集开放 `InternalsVisibleTo`，`Program` 声明为 `public partial class`，供 `WebApplicationFactory` 集成测试使用。

### 认证：grant_type 策略模式

`IIdentityValidator` 每个实现声明一个 `GrantType`，在 `ServiceCollectionExtensions` 里注册为 `IIdentityValidator`，`ValidatorFactory` 由注入的集合自动建字典。**新增登录方式只需实现接口 + 注册一行 DI，不改 TokenController**。已实现 `password` / `refresh_token`，`sms` / `wechat_code` 是骨架（缺短信网关与微信开放平台配置）。

三套并存的调用者身份模型，别混：

| 面向 | 认证方式 | 端点 |
|---|---|---|
| 业务网关 / 微服务 | `X-Admin-AppId` + `X-Admin-AppSecret` 头（BCrypt 校验，`GatewayValidationService`） | `/api/auth/*`、`/api/gateway/*` |
| 管理控制台 | Cookie `qz_admin_session` + `AdminSession` 授权策略（要求 `admin_access` claim） | `/api/admin/*` |
| 终端用户 | JwtBearer + `UserProfile` 策略 | `/api/profile/*` |

`/api/auth/token` 失败时返回 **HTTP 200 + `TokenResponse{Success=false, Message=...}`**，不是 4xx；错误文案是契约，见 `docs/modules/Auth/GetToken/06-CONVENTIONS.md`。`/api/auth/token` 上的 AppId 头是可选的：带了就校验，不带则跳过网关校验（只带 refresh_token 换票的调用方依赖这一点）。

### 多数据库 Provider

单一镜像，启动时按 `Database:Provider`（`PostgreSQL` / `MySQL` / `MariaDB` / `SQLite`）选一个 provider，不支持运行时切换、不做跨库搬迁。三条独立迁移链：

| Provider | 迁移程序集 |
|---|---|
| PostgreSQL（默认） | `QuantumZhou.Identity.Database` |
| MySQL / MariaDB | `QuantumZhou.Identity.Database.Migrations.MySql` |
| SQLite | `QuantumZhou.Identity.Database.Migrations.Sqlite` |

**改实体必须同时给三条链加迁移**，每个迁移项目各自带 `IDesignTimeDbContextFactory`（通过 `Database__Provider` / `Database__ServerVersion` / `Database__ConnectionString` 环境变量取连接信息）。迁移必须 expand-contract，保证滚动部署时相邻版本共存。SQLite 只支持单实例 + 实例本地磁盘。

配置契约见 `docs/adr/0001-multi-provider-persistence.md`：旧键（`PostgreSql:*`、`ConnectionStrings:Default`、`Database:Name`）会在 `BindDatabaseOptions` 里直接抛异常，没有兼容分支；配置缺失一律 fail-fast，不猜不降级。

### 大小写规范化

需要大小写不敏感的值（登录用户名、锁定用户名、AppId、ProviderName、昵称/备注搜索）统一用 `IdentityValueNormalizer.Normalize`（`FormC` + `ToUpperInvariant`）写入 `*_normalized` 列，唯一索引和查询走规范化列，**不依赖数据库 collation**；原始值保留展示。Refresh Token、AppSecret、`ProviderUserId`、`kid`、CorrelationId 保持大小写敏感。写涉及这些字段的查询时，永远比对 `XxxNormalized`。

### 启动顺序（`Program.cs`）

1. `AddConsulIfEnabled` 从 Consul KV `config/ruoyu`（含 `identity.json`）加载配置，失败回退本地缓存（`./data/consul`）；Consul 固定启用，`CONSUL_HTTP_ADDR` / `CONSUL_TOKEN` 等环境变量覆盖。
2. Serilog（Console + Loki，地址来自 `Loki:Uri`）。
3. `AddIdentityInfrastructure`：DI、限流、CORS、认证策略、OpenTelemetry。
4. `DatabaseInitializer.InitializeAsync`：建库 → 取 provider 级迁移锁（PG `pg_advisory_lock`，MySQL/MariaDB `GET_LOCK`）→ `SchemaMigrator`（碰撞预检 + 回填后再 `MigrateAsync`）→ bootstrap admin → 可选 `bootstrap-apps.json` 预置。迁移**无条件自动执行**，失败即启动失败。
5. `await keyManager.InitializationCompleted` 后才接请求，随后挂上 JwtBearer 的 `IssuerSigningKeyResolver`。

`data/` 目录（`master-key/`、`consul/`）由程序自建。RSA 私钥用 AES-GCM 加密存库，主密钥优先取环境变量 `RSA_MASTER_KEY`，缺失时落到 `data/master-key/master-key.json`（生产必须显式设置）。

### 中间件顺序（不要随意调整）

`CorrelationIdMiddleware` → `ExceptionHandlingMiddleware` → `UseCors` → `UseAuthentication` → `SensitiveHeaderRedactionMiddleware` → `UseAuthorization` → `UseRateLimiter` → `/health` → JWKS 专属限流 → `MapControllers`。CorrelationId 必须最靠前（CORS 预检和认证失败响应也要在 scope 内）；脱敏中间件必须在认证之后（`X-Admin-AppSecret` 此时已被消费）。SPA 静态文件通过 `MapWhen` 兜底，排除 `/api`、`/.well-known`、`/health`、`/metrics`。

## 编码约定

- 异常不回显给调用方：`ExceptionHandlingMiddleware` 把 `ArgumentException`→400、`InvalidOperationException`→409、其他→500，响应体是固定脱敏文案，原始异常只进结构化日志。
- 日志用结构化占位符，异常传对象（`LogError(ex, ...)`）。手机号、微信 OpenId 必须过 `Domain.SensitiveDataMasker`；Token / AppSecret / 验证码 / 密码一律不记录。数据库字段不受此约束。
- 限流拒绝要打 Warning，带 ClientIp 与命中的限流策略。
- 常量放 `Database/IdentityConstants.cs`；grant_type 用 snake_case，AuthMethod 用 PascalCase。
- **不写具体消费方**：文档、注释、提交信息里描述下游一律按角色（调用方 / 业务系统 / 下游微服务），不出现具体服务名、品牌名、它们的验证器配置或指向其仓库的链接。理由有两条：本仓库是 public repo，写出来等于替别家泄露接入细节；Identity 定位是面向任意系统的通用鉴权服务，点名某一家会让契约读起来像定制品。需要举例时用中性占位（`OrderService` 之类）。部署命名（`config/ruoyu`、`ruoyu-identity`、`ruoyu-net`）不在此列——那是本服务自身的部署身份与真实配置契约。

## 文档地图

`docs/README.md` 是索引。改功能前先看对应模块目录 `docs/modules/<域>/<功能>/`（01-FEATURE → 06-CONVENTIONS 六件套）；`docs/overview/` 服务级总览，`docs/database/` 表结构与迁移史，`docs/development/`（LocalSetup / Verification / ErrorHandling），`docs/adr/` 架构决策。`CONTEXT.md` 定义限界上下文用语——本仓库只有 **Account / Credential / Token / App Registration**，不出现 Student、Teacher、Role 等业务身份概念。
