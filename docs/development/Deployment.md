# 部署与运维

## 构建与部署

- Dockerfile：`backend/Host/Dockerfile`
- 部署脚本：`start.sh`（项目根目录）

## 运行模式选择

| 场景 | 模式 | 配置 |
|------|------|------|
| 本地开发、CI 测试 | 独立模式（默认） | 不设置 `CONSUL_MODE`，或显式 `CONSUL_MODE=Off` |
| 生产部署 | Consul 模式 | `CONSUL_MODE=On`，`CONSUL_HOST=host.docker.internal` |
| Consul 故障时 | 自动降级 | 无需人工干预，自动使用本地缓存启动 |

详见 [ConsulIntegration.md](./ConsulIntegration.md)。

---

## 独立模式部署（默认）

无需额外步骤，与改造前一致。

### start.sh 关键参数

```bash
# 数据库连接（__ 分隔符 → 层级配置）
-e Database__Provider=PostgreSQL
-e ConnectionStrings__PostgreSQL="Host=ruoyu-postgres;Port=5432;Database=ruoyu_identity;Username=postgres"

# 密钥
-e ADMIN_BOOTSTRAP_USERNAME=admin
-e ADMIN_BOOTSTRAP_PASSWORD=YourSecurePassword

# 日志
-e LOKI_URI=http://ruoyu-loki:3100

# 不设置 CONSUL_MODE = 独立模式
```

---

## Consul 模式部署

### 前置条件

1. Consul 容器已启动（`script/env-script/06-consul/start.sh`）
2. Consul KV 已推送初始配置（一次性 seed）

### start.sh 添加 Consul 参数

```bash
# Consul 集成
-e CONSUL_MODE=On
-e CONSUL_HOST=host.docker.internal
-e CONSUL_PORT=8500
-e CONSUL_SERVICE_NAME=QuantumZhou.Identity
-e CONSUL_TOKEN=<acl-token>
-e DB_PASSWORD=<postgres-password>
```

### Consul 缓存目录挂载

```bash
# 新增挂载：Consul 本地缓存（兜底用）
-v "$(pwd)/data/identity/consul:/app/data/consul"
```

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
  "ConnectionStrings": {
    "Default": "Host=ruoyu-postgres;Port=5432;Database=ruoyu_identity;Username=postgres;Password=postgres"
  }
}
```

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

## Teacher Portal 应用注册

```bash
# 必须设置的环境变量
export TEACHER_PORTAL_APP_ID=your-app-id
export TEACHER_PORTAL_APP_SECRET=your-app-secret
```

当 AppId 和 AppSecret 均未配置时，服务启动时跳过注册并输出警告日志。

---

## 日志配置

Identity 服务使用 Serilog，双写 Console + Grafana Loki。详见 [Configuration.md](./Configuration.md)。

---

## 健康检查

- 端点：`/health`（端口 5002）
- **独立模式**：数据库检查
- **Consul 模式（正常）**：数据库 + Consul 连通性
- **Consul 模式（降级）**：数据库检查 + 降级告警

---

## 监控

- Prometheus 指标端点：`http://<host>:5002/metrics`
- 已集成 OpenTelemetry（ASP.NET Core、Runtime、HttpClient）
- Consul 模式下，Consul 自动 HTTP 健康检查 `/health`

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

### 独立模式

1. 检查服务状态：`curl http://localhost:5002/health`
2. 查看日志：`docker logs ruoyu-identity | grep -i error`
3. 检查 KeyManager 初始化：`docker logs ruoyu-identity | grep "KeyManager initialization"`
4. 验证 JWKS 端点：`curl http://localhost:5002/.well-known/jwks`

### Consul 模式

1. 查看 Consul 连接状态：`curl http://localhost:5002/consul/status`
2. 检查服务注册：`curl http://localhost:8500/v1/catalog/services`
3. 检查健康失败原因：`curl http://localhost:8500/v1/health/checks/QuantumZhou.Identity`
4. 强制重连 Consul：调用 `POST /consul/cache/invalidate` 后重启服务

### 身份认证失败

1. JWKS 端点返回异常：`curl http://localhost:5002/.well-known/jwks`（应返回所有未过期密钥）
2. 确认各服务中 JWT Issuer 和 Audience 配置一致
3. 检查旧密钥轮换后旧 token 有效性：JWKS 端点返回所有未过期密钥（含已停用但未过期的），确保密钥轮换后旧 token 在过期前仍可验证
