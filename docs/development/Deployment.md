# 部署与运维

## 构建与部署

- Dockerfile：`backend/Host/Dockerfile`
- 部署脚本：`start.sh`（项目根目录）

## 启动要求

| 场景 | 模式 | 配置 |
|------|------|------|
| 项目根 `start.sh` / 容器部署 | Consul 集成 | 固定接入 Consul，共享配置从 Consul KV 提供，项目独有配置留在脚本内 |
| Consul 故障时 | 自动降级 | 使用本地缓存启动，无需切回脚本环境变量注入 |

详见 [ConsulIntegration.md](./ConsulIntegration.md)。

---

## Consul 集成部署

### 前置条件

1. Consul 容器已启动（`script/env-script/06-consul/start.sh`）
2. Consul KV 已推送初始配置（一次性 seed）

### start.sh 固定注入的 Consul 参数

```bash
-e CONSUL_HTTP_ADDR=host.docker.internal:8500
-e CONSUL_TOKEN=<acl-token>
```

> `CONSUL_SERVICE_NAME` 通常使用应用默认值，无需由 `start.sh` 重复注入。
>
> `start.sh` 不注入任何 `Database__*` 环境变量。Identity 从 Consul 的 `config/ruoyu/identity.json` 读取完整的 `Database:Provider`、`Database:ServerVersion` 和 `Database:ConnectionString`；这会覆盖 `appsettings.json` 中仅用于本地开发的回退值。旧的共享 `PostgreSql:*` 键会被 Identity 忽略。
>
> Consul 本地缓存默认写入容器内 `./data/consul`。`start.sh` 不再默认挂载宿主机目录；如果确实需要在“删除并重建容器”后保留缓存，再手动添加 volume。
>
> `CONSUL_HTTP_ADDR` 默认使用 `host.docker.internal:8500`，因此 Docker 启动参数必须补 `--add-host=host.docker.internal:host-gateway`，确保 Linux Docker 也能把该别名解析到宿主机网关。

### 验证 Consul 集成

```bash
# 检查服务注册
curl http://localhost:8500/v1/catalog/service/QuantumZhou.Identity

# 检查健康状态
curl http://localhost:5002/health

# 检查 Consul 连接状态
curl -b admin.cookies http://localhost:5002/consul/status
```

---

## 服务端口

| 端口 | 协议 | 用途 |
|------|------|------|
| 5002 | HTTP | 对外 REST API（含 JWT 签发、健康检查、Metrics、管理 API） |

---

## 数据库连接

`script/env-script/06-consul/config/kv/identity.json`：

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=ruoyu-postgres;Port=5432;Database=ruoyu_identity;Username=postgres;Password=postgres"
  }
}
```

> 三个数据库配置键必须作为一个整体提供。SQLite 不配置 `ServerVersion`，连接字符串使用实例本地文件路径。

---

## JWT 配置

```json
{
  "Jwt": {
    "Issuer": "QuantumZhou.Identity",
    "Audience": "QuantumZhou.microservices",
    "TokenExpirationHours": 2
  },
  "RefreshToken": {
    "ExpirationDays": 7
  }
}
```

---

## 管理员引导账户

管理员密码不再硬编码于配置文件，通过环境变量传入。

```bash
# 必须设置的环境变量
export ADMIN_BOOTSTRAP_USERNAME=admin
export ADMIN_BOOTSTRAP_PASSWORD=YourSecurePassword
```

`appsettings.json` 中 `AdminBootstrap:Password` 默认为空，`PostConfigure` 从环境变量覆盖。

> **只对全新库生效**：`DatabaseInitializer.EnsureBootstrapAdminAsync` 是幂等的——同名账号已存在就跳过。
> 改 `ADMIN_BOOTSTRAP_PASSWORD` **不会**改掉已有 admin 的密码，轮换必须走管理控制台改密。

---

## 部署凭据注入

`start.sh` 不内置任何凭据（本仓库是 public repo，写死等同公开）。以下变量在脚本最前面展开，
**缺值时在停止旧容器之前就退出**，正在运行的容器不受影响：

| 环境变量 | 必填 | 缺失行为 | 说明 |
|---|---|---|---|
| `ADMIN_BOOTSTRAP_PASSWORD` | 是（非空） | 部署失败 | 初始管理员密码 |
| `SMS_BYPASS_CODE` | 是（可为空串） | 部署失败 | 短信绕过码；显式设为空串即关闭绕过 |
| `SMS_BYPASS_PHONES` | 是（可为空串） | 部署失败 | 绕过白名单，逗号分隔；空串即关闭绕过 |
| `ADMIN_BOOTSTRAP_USERNAME` | 否 | 默认 `admin` | 初始管理员用户名 |
| `CONSUL_TOKEN` | 否 | 默认空 | Consul ACL token |

`${VAR:?}`（必填非空）与 `${VAR?}`（必须设置，允许空串）的区别是刻意的：关闭短信绕过不需要改脚本，
设个空 secret 即可。

### CI/CD（GitHub Actions）

`.github/workflows/ci.yml` 是本仓库唯一的流水线（原 Jenkins 流水线已移除），**只做构建与测试，不做部署**：

| job | runner | 触发 | 说明 |
|---|---|---|---|
| `build-test` | `ubuntu-latest`（托管） | push + PR，含 fork PR | 构建镜像 + 单元测试，约 90 秒 |
| `database-contracts` | `ubuntu-latest`（托管） | push + PR | 四库契约矩阵（PG / MySQL / MariaDB / SQLite），约 30 秒 |

两个 job 都跑在 GitHub 托管 runner 上——public 仓库不限量，本项目不需要自备构建机。
`database-contracts` 只在 `build-test` 通过后才跑，构建挂了就没必要拉四个数据库镜像。

> **不要往这条流水线里加 self-hosted runner 的 job。** public 仓库 + self-hosted runner 是高危组合：
> 陌生人 fork 后改一行 workflow 提 PR，就可能在那台机器上执行任意代码。
> 部署改由人工执行（见下节），代价是多敲几条命令，换来的是内网没有对外的执行入口。
> 另外 public 仓库的 workflow 日志全网可读，任何新增步骤都不得回显 token、密码或响应体。

托管 runner 上跑 Testcontainers 有两个坑，`ci.yml` 里已处理，改动时不要顺手删掉：

- `TESTCONTAINERS_RYUK_DISABLED=true`。托管 runner 是一次性 VM，整机销毁，不需要 Ryuk 回收容器；
  而 Ryuk 在第一个测试之前就要拉镜像并等它连上，失败时**零输出**，表现为整个 job 静默到超时。
- `--blame-hang --blame-hang-timeout 5m`。`dotnet test` 缓冲输出，没有它的话任何卡死都只能看到一片空白。

本地跑契约矩阵（需要本机 Docker）：

```bash
RUN_IDENTITY_DATABASE_CONTRACTS=true \
dotnet test backend/Tests/integration/QuantumZhou.Identity.IntegrationTests.csproj \
  --filter 'FullyQualifiedName~DatabaseContractTests'
```

> **非 ASCII 字面量一律用转义写法**（如 `\u00C9` 而不是直接写 `É`）。
> 该矩阵此前从未真正跑通，恢复运行后暴露的第一个失败就是这个坑：
> `ServerDatabaseContractTests` 里的 `"CAFÉ"` 曾被误按 GBK 解码再存回 UTF-8，
> 变成了汉字 `"CAF脡"`(U+8121)，测试于是在查询一个从未写入过的值。
>
> 另外，向 PostgreSQL 的 `timestamp with time zone` 写 `DateTimeOffset` 时必须是
> `Offset=0`，Npgsql 会拒绝非零偏移而 MySQL 不会——这是 provider 间的真实行为差异。
> 产品代码全程使用 `DateTimeOffset.UtcNow`，不依赖该差异，新增写入路径请保持这个约定。

### 发布（人工执行）

镜像 `quantumzhou.identity:<tag>` 不走 registry，`start.sh` 直接用本机镜像，
因此**构建和部署必须在同一台机器上**——也就是部署机本身。CI 那次构建只是 PR 期的早失败信号。

在部署机上：

```bash
cd /path/to/QuantumZhou.Identity
git pull

# 凭据来自密钥库，不写进任何文件；见上表
export ADMIN_BOOTSTRAP_PASSWORD=...
export SMS_BYPASS_CODE=...
export SMS_BYPASS_PHONES=...
export CONSUL_TOKEN=...

bash build.sh
bash start.sh
docker ps --filter 'name=ruoyu-identity'
```

`start.sh` 在 `docker stop` **之前**展开这四个变量，任何一个没设置都会在停旧容器前退出，
不会把服务停在半路。变量的必填语义见上表。

发布后按 [Verification](Verification.md) 做冒烟检查（OIDC discovery、JWKS、admin 登录）。

> 这四个变量不再需要配成 GitHub Secrets——流水线里已经没有会用到它们的 job 了。
> 若此前配过，可以删掉，减少一处凭据留存点。

---

## SMS 绕过验证码

绕过码用于免真实短信网关的联调与 CI smoke（生产环境 `ISmsSender` 是 `ThrowingSmsSender`，发不出真实短信）。
**绕过码必须配合手机号白名单使用**，两者缺一则绕过整体禁用：

```bash
export SMS_BYPASS_CODE=<从密钥库取，不写进仓库>
export SMS_BYPASS_PHONES=13800138000,13900139000
```

行为约定：

- `Sms:BypassCode` 为空 **或** `Sms:BypassPhones` 为空 → 绕过完全禁用（配了码没配名单不等于放行所有号码）。
- 白名单外的号码即使提交了正确的绕过码，也会落回正常 OTP 校验并失败。
- 绕过路径不经过 `DbOtpService`，`MaxAttempts` / `LockoutSeconds` 对它无效——白名单是唯一收口手段，
  名单里只能放测试号码。
- `/api/auth/token` 必须先通过 AppId/AppSecret 应用认证；白名单里的号码仍应只放测试账号，因为持有应用凭据和绕过码即可登录。

配置项说明见 [Configuration.md](./Configuration.md)（含 Consul 与环境变量的优先级陷阱）。

---

## 数据目录挂载

Identity 通过单一 `data/` 目录挂载实现数据持久化。`start.sh` 将宿主机 `${DATA_DIR}`（即 `start.sh` 同级的 `data/` 目录）挂载到容器内 `/app/data`：

```bash
-v "${DATA_DIR}:/app/data"
```

`data/` 目录的用途：
- 持久化 RSA 主密钥：`master-key/master-key.json`（由 `KeyManager` 在写入前自动创建 `master-key/` 子目录）
- 读取预置应用配置：`bootstrap-apps.json`（可选，文件不存在时跳过预置）
- Consul 本地缓存：`consul/cache.json`（降级时使用）

`data/` 目录由部署脚本（CI / 生产）管理：
- 启动容器前 `data/` 目录必须存在（`start.sh` 负责 `mkdir -p "$DATA_DIR"` 并 `chown -R 1000:1000 "$DATA_DIR"`，确保容器内 UID 1000 有写权限）
- 部署脚本按需往 `data/` 目录写入预置文件（如 `bootstrap-apps.json`）
- 启动脚本**不感知** `data/` 目录下有哪些具体文件，也**不**创建业务子目录（如 `master-key/`）

> 容器内 ContentRoot 为 `/app`，程序内所有相对路径（`data/master-key/master-key.json`、`data/bootstrap-apps.json`、`data/consul/cache.json`）解析为容器内 `/app/data/...`，与挂载点一致。

---

## 应用注册预置（Bootstrap Apps）

首次部署时，通过 `data/bootstrap-apps.json` 文件预置基础应用注册信息（各业务 BFF、管理控制台的应用凭据）。该文件位于 `data/` 目录下，随整个 `data/` 目录一并由 `start.sh` 挂载到容器。运行时动态管理仍通过 Admin API (`POST /api/admin/apps`) 完成。

详见 [Configuration.md](./Configuration.md) "Bootstrap Apps 配置"章节。

### CI 环境测试凭据

CI 环境在启动 Identity 容器前将 `bootstrap-apps.json` 写入 `data/` 目录，凭据从 CI 密钥库读取：

```bash
# 凭据由 CI 密钥库持有，不进仓库（本仓库是 public repo）
mkdir -p ./data
cat > ./data/bootstrap-apps.json <<EOF
{
  "apps": [
    {
      "appId": "${PORTAL_APP_ID}",
      "appSecret": "${PORTAL_APP_SECRET}",
      "appName": "${PORTAL_APP_NAME}",
      "callbackUrl": "http://${PORTAL_BFF_HOST}:5004/api/auth/callback"
    }
  ]
}
EOF
```

文件随 `data/` 目录挂载到容器 `/app/data`，程序读取 `data/bootstrap-apps.json`。

> **复用策略**：多个业务 BFF 在 CI 环境中可复用同一组凭据。`GatewayValidationService` 仅校验 AppId 注册状态、活跃状态、过期时间和 AppSecret 哈希，不绑定具体业务系统，因此 BFF 共享凭据是安全的。

> **生产环境**：部署脚本将 `bootstrap-apps.json` 写入 `data/` 目录（`chmod 600`）或通过 Admin API (`POST /api/admin/apps`) 为每个业务系统单独注册应用，AppSecret 仅在创建时返回一次。

### Bootstrap Admin 角色注入

`AdminBootstrap:Username` 配置的 bootstrap admin 账号是"超级管理员"，在密码登录和刷新令牌换票时由 Identity **无条件注入** `role:admin`，绕过 callback 机制。因此：

- bootstrap admin **无需配置** `AdminPortal:AdminUserIds` 即可获得 `role:admin`
- bootstrap admin 无论从哪个业务应用登录，JWT 都包含 `role:admin`
- bootstrap admin 使用 Refresh Token 换票后，新 JWT **仍包含** `role:admin`（refresh grant 使用已验证账户 ID 与 bootstrap 账户 ID 比较，不依赖请求体 `username`）
- 注入前会检查是否已存在 `role=admin`，避免重复
- 匹配使用大小写不敏感比较（`StringComparison.OrdinalIgnoreCase`）；配置为空时跳过注入，保持原行为
- SMS/微信 grant 不触发 bootstrap admin 注入，bootstrap account 身份不扩大到这两类 grant
- `AdminUserIds` 白名单仍保留，用于扩展**非 bootstrap** 的二级管理员账号（需 admin_portal callback 注入）

> **自动刷新会话**：调用方在 Access Token 到期后提交 Refresh Token，并继续携带签发该令牌的 AppId/AppSecret 调用 `POST /api/auth/token`（无需补传用户名）。Identity 会校验 refresh token 的 AppId 绑定，并基于已验证账户 ID 重新识别 bootstrap admin；跨应用换票会被拒绝。

### CI 联调验证流程

CI smoke test 依赖以下 Identity 能力（均已在 CI 环境配置）：

1. **JWKS 获取**：`GET /.well-known/jwks`（BFF 启动时自动发现）
2. **SMS 固定验证码**：`SMS_BYPASS_CODE` + `SMS_BYPASS_PHONES`，均由 CI 的密钥库注入。
   只有白名单内的测试号码能用绕过码登录——**不再是任意手机号**。调用方侧的 smoke
   如果用了名单外的号码，需要把该号码加进 `SMS_BYPASS_PHONES` 或改用真实 OTP 流程。
3. **管理员引导账户**：用户名 `admin`，密码由 `ADMIN_BOOTSTRAP_PASSWORD` 注入（DatabaseInitializer 自动种子，
   仅对全新库生效；已存在的 admin 不会被改写，改密要走管理控制台）
4. **数据目录挂载**：`data/` 目录（含 `master-key/` 由 KeyManager 自动创建、预置 `bootstrap-apps.json` 由 DatabaseInitializer 自动种子）
5. **Bootstrap Admin 自动注入**：`AdminBootstrap:Username` 配置的账号密码登录时自动获得 `role:admin`（无需额外配置白名单）

跨服务联调方案由调用方各自维护，不在本仓库范围内。

---

## 日志配置

Identity 服务使用 Serilog，双写 Console + Grafana Loki。详见 [Configuration.md](./Configuration.md)。

---

## 健康检查

- 端点：`/health`（端口 5002）
- **Consul 正常**：数据库 + Consul 连通性
- **Consul 降级**：数据库检查 + 降级告警

---

## 监控

- Prometheus 指标端点：`http://<host>:5002/metrics`
- 已集成 OpenTelemetry（ASP.NET Core、Runtime、HttpClient）
- Consul 集成下，Consul 自动 HTTP 健康检查 `/health`

---

## 数据库备份与恢复

```bash
# 备份
docker exec ruoyu-postgres pg_dump -U postgres quantumzhou_identity | gzip > backup_identity_$(date +%Y%m%d_%H%M%S).sql.gz

# 恢复
gunzip -c backup_identity_20260101_020000.sql.gz | docker exec -i ruoyu-postgres psql -U postgres -d quantumzhou_identity
```

---

## Consul 运维

### 连接 Consul 模式

当 Consul 暂时不可用时，Identity 服务自动降级：

1. 控制台输出 `[WARN] Consul connection failed, using local cache`
2. 使用 `data/consul/cache.json`（最后一次成功获取的配置）启动
3. Consul 恢复后，服务**不会**自动重连，需要重启服务以重新拉取最新配置
4. 如需清除降级缓存，使用管理员会话调用 `POST /consul/cache/invalidate`；该操作不会热重载当前配置，下次启动会重新拉取

### Consul 快照备份

```bash
# 备份 Consul 全部 KV + Catalog
docker exec ruoyu-consul consul snapshot save /tmp/consul-backup.snap
docker cp ruoyu-consul:/tmp/consul-backup.snap ./data/consul/backup-$(date +%Y%m%d).snap

# 恢复
docker cp ./data/consul/backup-20260101.snap ruoyu-consul:/tmp/consul-restore.snap
docker exec ruoyu-consul consul snapshot restore /tmp/consul-restore.snap
```

---

## 常见问题排查

### Consul 模式

1. 查看 Consul 连接状态：`curl -b admin.cookies http://localhost:5002/consul/status`
2. 检查服务注册：`curl http://localhost:8500/v1/catalog/services`
3. 检查健康失败原因：`curl http://localhost:8500/v1/health/checks/QuantumZhou.Identity`
4. 清除降级缓存：使用管理员会话调用 `POST /consul/cache/invalidate`，确认 Consul 可用后再重启服务

### 身份认证失败

1. JWKS 端点返回异常：`curl http://localhost:5002/.well-known/jwks`（应返回所有未过期密钥）
2. 确认各服务中 JWT Issuer 和 Audience 配置一致
3. 检查旧密钥轮换后旧 token 有效性：JWKS 端点返回所有未过期密钥（含已停用但未过期的），确保密钥轮换后旧 token 在过期前仍可验证
