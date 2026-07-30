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
> `Database:Provider` 使用程序默认值；`Database:Name` 如需覆盖可由 `start.sh` 注入。PostgreSQL Host / Port / Username / Password 和 Loki 地址属于共享基础设施配置，继续由 Consul KV 提供。
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
curl http://localhost:5002/consul/status
```

---

## 服务端口

| 端口 | 协议 | 用途 |
|------|------|------|
| 5002 | HTTP | 对外 REST API（含 JWT 签发、健康检查、Metrics、管理 API） |

---

## 数据库连接

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "Name": "quantumzhou_identity"
  },
  "PostgreSql": {
    "Host": "ruoyu-postgres",
    "Port": 5432,
    "Username": "postgres",
    "Password": "postgres"
  }
}
```

> 其中 `Database:Provider` 使用程序默认值，`Database:Name` 可按需由 Identity `start.sh` 覆盖；`PostgreSql:*` 由 Consul `config/ruoyu/shared.json` 提供。

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

---

## SMS 绕过验证码（仅限开发/预发布）

```bash
# 开发环境可设置绕过码，生产环境必须留空
export SMS_BYPASS_CODE=666666
```

`Sms:BypassCode` 和 `SMS_BYPASS_CODE` 为空时，绕过逻辑完全禁用。

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

首次部署时，通过 `data/bootstrap-apps.json` 文件预置基础应用注册信息（如 Teacher Portal、Admin Portal 的应用凭据）。该文件位于 `data/` 目录下，随整个 `data/` 目录一并由 `start.sh` 挂载到容器。运行时动态管理仍通过 Admin API (`POST /api/admin/apps`) 完成。

详见 [Configuration.md](./Configuration.md) "Bootstrap Apps 配置"章节。

### CI 环境测试凭据

CI 环境（Jenkins）在启动 Identity 容器前将 `bootstrap-apps.json` 写入 `data/` 目录：

```bash
# CI 脚本中生成（凭据由 CI 脚本持有，不进仓库）
mkdir -p ./data
cat > ./data/bootstrap-apps.json <<'EOF'
{
  "apps": [
    {
      "appId": "a6eab9bd87404c0ababc910114d11a62",
      "appSecret": "cGzoAwXaP+PahtD3qXYVY75IJiPWtfbt/4SIt+WrKoQ=",
      "appName": "Teacher Portal",
      "callbackUrl": "http://ruoyu-teacher-api:5004/api/auth/callback"
    }
  ]
}
EOF
```

文件随 `data/` 目录挂载到容器 `/app/data`，程序读取 `data/bootstrap-apps.json`。

> **复用策略**：Teacher Portal 和 Assistant Portal 在 CI 环境中复用同一组凭据。`GatewayValidationService` 仅校验 AppId 注册状态、活跃状态、过期时间和 AppSecret 哈希，不绑定具体业务系统，因此 BFF 共享凭据是安全的。

> **生产环境**：部署脚本将 `bootstrap-apps.json` 写入 `data/` 目录（`chmod 600`）或通过 Admin API (`POST /api/admin/apps`) 为每个业务系统单独注册应用，AppSecret 仅在创建时返回一次。

### Bootstrap Admin 角色注入

`AdminBootstrap:Username` 配置的 bootstrap admin 账号是"超级管理员"，在密码登录和刷新令牌换票时由 Identity **无条件注入** `role:admin`，绕过 callback 机制。因此：

- bootstrap admin **无需配置** `AdminPortal:AdminUserIds` 即可获得 `role:admin`
- bootstrap admin 无论从哪个 portal（teacher_portal / admin_portal 等）登录，JWT 都包含 `role:admin`
- bootstrap admin 使用 Refresh Token 换票后，新 JWT **仍包含** `role:admin`（refresh grant 使用已验证账户 ID 与 bootstrap 账户 ID 比较，不依赖请求体 `username`）
- 注入前会检查是否已存在 `role=admin`，避免重复
- 匹配使用大小写不敏感比较（`StringComparison.OrdinalIgnoreCase`）；配置为空时跳过注入，保持原行为
- SMS/微信 grant 不触发 bootstrap admin 注入，bootstrap account 身份不扩大到这两类 grant
- `AdminUserIds` 白名单仍保留，用于扩展**非 bootstrap** 的二级管理员账号（需 admin_portal callback 注入）

> **DocLibrary 自动刷新会话**：DocLibrary 管理后台在 Access Token 到期后只提交 Refresh Token（不补传用户名）调用 `POST /api/auth/token`。由于 Identity 在 refresh grant 中基于已验证账户 ID 重新识别 bootstrap admin，DocLibrary 管理员会话可以连续刷新而不丢失 `role=admin`，同时普通账户无法通过伪造 `username=admin` 提权。

### CI 联调验证流程

CI smoke test 依赖以下 Identity 能力（均已在 CI 环境配置）：

1. **JWKS 获取**：`GET /.well-known/jwks`（BFF 启动时自动发现）
2. **SMS 固定验证码**：`SMS_BYPASS_CODE=666666`（任意手机号登录）
3. **管理员引导账户**：`admin/Qwer1234`（DatabaseInitializer 自动种子）
4. **数据目录挂载**：`data/` 目录（含 `master-key/` 由 KeyManager 自动创建、预置 `bootstrap-apps.json` 由 DatabaseInitializer 自动种子）
5. **Bootstrap Admin 自动注入**：`AdminBootstrap:Username` 配置的账号密码登录时自动获得 `role:admin`（无需额外配置白名单）

详见 [CI Smoke Test 联调方案](../../../../../tests/integration/docs/ci-smoke-test.md)。

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
4. 如需不重启刷新，调用 `POST /consul/cache/invalidate` 强制清空缓存并立即重连 Consul

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

1. 查看 Consul 连接状态：`curl http://localhost:5002/consul/status`
2. 检查服务注册：`curl http://localhost:8500/v1/catalog/services`
3. 检查健康失败原因：`curl http://localhost:8500/v1/health/checks/QuantumZhou.Identity`
4. 强制重连 Consul：调用 `POST /consul/cache/invalidate` 后重启服务

### 身份认证失败

1. JWKS 端点返回异常：`curl http://localhost:5002/.well-known/jwks`（应返回所有未过期密钥）
2. 确认各服务中 JWT Issuer 和 Audience 配置一致
3. 检查旧密钥轮换后旧 token 有效性：JWKS 端点返回所有未过期密钥（含已停用但未过期的），确保密钥轮换后旧 token 在过期前仍可验证
