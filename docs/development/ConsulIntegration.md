# Consul 服务发现 + 配置中心集成

> 目标：引入 Consul 作为基础设施组件（与 Loki / PostgreSQL 同级），集中管理非密钥配置与服务注册，同时保留完全独立运行能力。

## 状态

- **决策**：已接受（2026-07-11），参见 `docs/env/consul.md`
- **实施状态**：决策已接受，待实施
- **负责人**：待分配

## 1. 三种运行模式

Identity 服务支持三种配置模式，由环境变量 `CONSUL_MODE` 控制：

| 模式 | `CONSUL_MODE` 值 | 依赖 Consul | 说明 |
|------|------------------|------------|------|
| **独立模式（默认）** | `Off`（或不设置）| ❌ | 完全自给自足，按原机制加载 `appsettings.json` → 环境变量；不发起任何 Consul 相关网络调用 |
| **Consul 模式** | `On` | ✅ | 启动时从 Consul KV 加载配置、注册服务、开启健康检查；Consul 不可达时回退到本地缓存 |
| **本地缓存回退** | `On` 但 Consul 不可达 | ❌（降级）| Consul 连接失败时，自动使用上一次成功获取的配置缓存文件启动；日志告警但不阻断 |

> **原则**：独立模式永远是默认且可用的。开启 Consul 是"增强"而非"必需"；Consul 挂了服务照样跑。

## 2. 启动时序

### 2.1 独立模式（默认，无 CONSUL_MODE 或 =Off）

```
容器启动
  → WebApplication.CreateBuilder 加载 appsettings.json
  → appsettings.{Environment}.json 覆盖
  → 环境变量（__ 分隔符）覆盖
  → 原有启动流程（KeyManager / AutoMigrate / Bootstrap 等）
  → 对外服务
```

与改造前完全一致，无任何新增依赖或网络调用。

### 2.2 Consul 模式（CONSUL_MODE=On）

```
容器启动
  → WebApplication.CreateBuilder 加载 appsettings.json（本地 Layer 0）
  → 尝试连接 Consul（地址来自 CONSUL_HOST 环境变量）
  │
  ├── 成功
  │   → 从 Consul KV 加载 config/ruoyu/QuantumZhou.Identity/{profile}/*  → 合并到 IConfiguration
  │   → 生成本地缓存文件 data/consul/cache.json（供下次启动兜底）
  │   → 向 Consul Catalog 注册服务 + HTTP 健康检查 /health
  │   → 继续原有启动流程
  │   → 对外服务（运行时 CONSUL_MODE=On 时 /health 会额外报告 Consul 连接状态）
  │
  └── 失败（Consul 不可达 / 超时 / ACL 拒绝）
      → 读取 data/consul/cache.json（上一次成功获取的快照）
      │   ├── 缓存存在且有效
      │   → 使用缓存配置启动（降级，不注册服务）
      │   → 日志告警：[Consul] 连接不可用，使用本地缓存启动
      │
      │   └── 缓存不存在或已损坏
      → 使用 appsettings.json 默认值启动（纯降级）
      → 日志告警：[Consul] 连接不可用且无缓存，使用本地配置启动
```

### 2.3 三种模式对比

| 维度 | 独立模式 | Consul 模式（正常） | Consul 模式（降级） |
|------|---------|-------------------|-------------------|
| Consul 网络调用 | 0 次 | 启动时 N+1 次（N=KV keys） | 0 次（快速失败） |
| 配置来源 | appsettings + 环境变量 | Consul KV（优先）+ appsettings（兜底） | 本地缓存（优先）+ appsettings（兜底） |
| 服务注册到 Consul | ❌ | ✅ | ❌ |
| 动态配置刷新 | ❌ | ✅（IOptionsMonitor） | ❌ |
| 对服务可用性影响 | 无 | 无 | 无 |
| 适用场景 | 开发环境、单机调试、灾难恢复 | 生产部署、多服务协同 | Consul 正在重启/网络抖动时 |

## 3. 环境变量

| 变量 | 默认值 | 必需 | 说明 |
|------|--------|------|------|
| `CONSUL_MODE` | `Off` | 否 | `Off` = 独立模式；`On` = 启用 Consul |
| `CONSUL_HOST` | `ruoyu-consul` | 否 | Consul HTTP API 地址（容器名或 IP） |
| `CONSUL_PORT` | `8500` | 否 | Consul HTTP API 端口 |
| `CONSUL_SERVICE_NAME` | `QuantumZhou.Identity` | 否 | 服务注册名称 |
| `CONSUL_SERVICE_ID` | 自动生成 | 否 | 服务实例 ID（多实例时需保证唯一） |
| `CONSUL_KV_PREFIX` | `config/ruoyu` | 否 | KV 路径前缀（与项目全局约定一致） |
| `CONSUL_PROFILE` | 与 `ASPNETCORE_ENVIRONMENT` 一致 | 否 | 用于 KV 路径环境段（如 `dev` / `prod`） |
| `CONSUL_TIMEOUT_MS` | `3000` | 否 | 单次请求超时（毫秒） |
| `CONSUL_RETRY_COUNT` | `3` | 否 | 连接重试次数（指数退避） |
| `CONSUL_ENABLE_CACHE` | `true` | 否 | 是否启用本地缓存兜底 |

> **独立模式下以上所有变量均不生效**，即使设置了也忽略。

## 4. 配置分层（Consul 模式生效时）

完整优先级（从高到低）：

```
1. 命令行参数（最高）
2. 短环境变量（DB_PASSWORD, ADMIN_BOOTSTRAP_*, SMS_BYPASS_CODE 等）—— 密钥
3. __ 分隔符环境变量（Database__Provider 等）
4. Consul KV（config/ruoyu/QuantumZhou.Identity/{profile}/{key}）
5. 本地缓存文件（data/consul/cache.json，Consul 不可达时使用）
6. appsettings.{Environment}.json（如 appsettings.Production.json）
7. appsettings.json（最低 —— 开发默认值）
```

> **Consul KV 优先级高于环境变量**：意味着可以把部分配置从 env 迁移到 Consul KV 后，通过 KV 覆盖 env。但**短环境变量（Layer 2 密钥）优先级高于 Consul KV**，确保密钥始终走环境变量。

## 5. Consul KV 映射规则

### 5.1 路径格式

```
config/ruoyu/{ServiceName}/{Profile}/
├── serilog.json          → Serilog 完整配置节
├── feature-flags.json    → 功能开关
├── downstream.json       ↓ 下游服务地址（当前 Identity 暂无下游）
└── grpc-settings.json    → gRPC 全局策略
```

`Profile` = `ASPNETCORE_ENVIRONMENT` 的小写（`Development` → `dev`，`Production` → `prod`）。

### 5.2 KV → IConfiguration 映射

Consul KV 的 Value 必须是 JSON 字符串。映射规则：

| Consul KV | IConfiguration 覆盖范围 |
|-----------|----------------------|
| `config/ruoyu/QuantumZhou.Identity/prod/serilog.json` | `Serilog:*` |
| `config/ruoyu/QuantumZhou.Identity/prod/feature-flags.json` | `FeatureFlags:*` |
| `config/ruoyu/_global/feature-flags.json` | `FeatureFlags:*`（全局，优先级低于服务级） |

### 5.3 密钥**不**进入 Consul

以下配置**永远**通过环境变量注入，不走 Consul：

- `DB_PASSWORD`（数据库密码）
- `RSA_MASTER_KEY`（RSA 主密钥）
- `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD`（初始管理员）
- `Sms:BypassCode`（绕过验证码，仅开发）
- `TEACHER_PORTAL_APP_ID` / `TEACHER_PORTAL_APP_SECRET`（应用注册密钥）
- `WECHAT_SECRET`（微信应用密钥）

## 6. 本地缓存机制

### 6.1 存储位置

```
data/
└── consul/
    ├── cache.json              ← 最后成功获取的配置快照
    └── cache.metadata.json     ← 元数据（获取时间、Consul 地址、版本号）
```

### 6.2 缓存写入时机

- 每次成功从 Consul 拉取配置后**同步**写入 `cache.json`
- 写入使用**原子替换**（先写 `cache.json.tmp`，再 `rename` 为 `cache.json`），防止写入过程中断导致缓存损坏

### 6.3 缓存读取时机

- Consul 连接失败 / 超时 / 返回错误时触发
- 如果 `cache.json` 损坏或 JSON 解析失败，跳过缓存、直接用本地 appsettings 启动（输出 CRITICAL 级别日志）

### 6.4 缓存失效策略

- 默认**不设置 TTL**：只要 Consul 可达，始终从 Consul 获取最新配置
- 缓存只在"Consul 不可达时"使用，不主动过期
- 可通过 `CONSUL_CACHE_MAX_AGE_HOURS`（未来扩展）设置缓存最大年龄

## 7. Consul 集成实现规格

### 7.1 新增文件

| 文件 | 说明 |
|------|------|
| `Host/Configuration/ConsulConfigurationProvider.cs` | 自定义 .NET 配置提供程序，从 Consul KV 拉取并转换为 IConfiguration 数据 |
| `Host/Configuration/ConsulConfigurationSource.cs` | 配置源包装，供 `builder.Configuration.AddConsul()` 式调用 |
| `Host/Configuration/LocalConfigCache.cs` | 本地缓存读写（原子替换） |
| `Host/Configuration/ConsulServiceRegistrar.cs` | 启动时注册服务到 Consul Catalog + 健康检查 |
| `Host/Configuration/ConsulOptions.cs` | 强类型配置（对应 appsettings.json `Consul:` 节） |

### 7.2 NuGet 依赖

> **不引入 Steeltoe**。原因：Identity 的 Consul 集成点较少（仅配置 + 服务注册），生产环境要求强类型配置和显式缓存控制，重量级 Steeltoe 引入过多横切关注点（Actuator/Endpoint 等我们用不到的东西）。轻量自定义实现约 200 行代码，零新增依赖（使用 `HttpClient` 消费 Consul REST API）。

### 7.3 配置扩展方法

```csharp
// 使用示例（在 Program.cs 中）
builder.Configuration.AddConsulConfiguration(builder.Configuration);
```

### 7.4 服务端点（Consul 模式 + 正常连接时）

新增管理端点，仅 `CONSUL_MODE=On` 时映射：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/consul/status` | GET | 返回 Consul 连接状态、最后成功时间、缓存年龄 |
| `/consul/cache/invalidate` | POST | 强制清空本地缓存（下次启动时重新拉取）|

> `/health` 端点**始终映射**（三种模式），Consul 模式正常时额外输出 Consul 连通性信息。

## 8. 健康检查

### 8.1 gRPC / HTTP Health Check

Consul 模式正常时，向 Consul Catalog 注册 HTTP 健康检查：

```
GET http://<容器IP>:5002/health
间隔: 5s
超时: 2s
连续失败 3 次后摘除服务
```

### 8.2 /health 端点响应

- **独立模式**：与当前一致（仅数据库检查）
- **Consul 模式（正常）**：数据库检查 + Consul 连通性
- **Consul 模式（降级）**：数据库检查（不连 Consul）

```json
// Consul 模式正常时
{
  "status": "Healthy",
  "results": [
    { "name": "database", "status": "Healthy" },
    { "name": "consul", "status": "Healthy", "description": "Connected to ruoyu-consul:8500" }
  ]
}

// Consul 模式降级时
{
  "status": "Healthy",
  "results": [
    { "name": "database", "status": "Healthy" },
    { "name": "consul", "status": "Degraded", "description": "Using local cache, Consul unreachable" }
  ]
}
```

## 9. start.sh 改造

### 9.1 新增环境变量（start.sh 定义默认值，不强制）

```bash
# Consul（可选，不设置=保持独立模式）
CONSUL_MODE="${CONSUL_MODE:-Off}"              # Off 或 On
CONSUL_HOST="${CONSUL_HOST:-ruoyu-consul}"
CONSUL_PORT="${CONSUL_PORT:-8500}"
CONSUL_SERVICE_NAME="${CONSUL_SERVICE_NAME:-QuantumZhou.Identity}"
```

### 9.2 启动命令

```bash
if [ "$CONSUL_MODE" = "On" ]; then
  CONSUL_ENV_FLAGS=" \
    -e CONSUL_MODE=On \
    -e CONSUL_HOST=${CONSUL_HOST} \
    -e CONSUL_PORT=${CONSUL_PORT} \
    -e CONSUL_SERVICE_NAME=${CONSUL_SERVICE_NAME} \
    -e CONSUL_KV_PREFIX=config/ruoyu"
else
  CONSUL_ENV_FLAGS=""
fi

docker run -d \
  ...原有参数... \
  ${CONSUL_ENV_FLAGS} \
  "$IMAGE_NAME"
```

### 9.3 原有行为不受影响

不设置 `CONSUL_MODE` 或 `CONSUL_MODE=Off` 时，`CONSUL_ENV_FLAGS` 为空，启动命令与改造前完全一致。

## 10. 部署流程

### 10.1 Consul 容器先行启动

```bash
# 基础设施层（含 Consul）
script/env-script/06-consul/start.sh    # 新增
script/env-script/01-postgres/start.sh
script/env-script/02-seaweedfs/start.sh
# ...
```

### 10.2 Consul KV 种子配置推送

首次部署时，需要把初始配置推送到 Consul KV（一次性）：

```bash
# 连接 Consul
CONSUL_HTTP_ADDR=http://localhost:8500

# 推送 Identity 生产环境配置
consul kv put config/ruoyu/QuantumZhou.Identity/prod/serilog.json '{"MinimumLevel":{"Default":"Information"}}'
consul kv put config/ruoyu/_global/feature-flags.json '{"EnableNewLogin":true}'
# ...
```

可在初始部署后将这些脚本沉淀为 `script/env-script/06-consul/seed-identity-kv.sh`。

### 10.3 Identity 容器启动（Consul 模式）

```bash
IDENTITY_IMAGE="quantumzhou.identity:20260502"

docker run -d \
  --name ruoyu-identity \
  --restart unless-stopped \
  --network ruoyu-net \
  -p 10891:5002 \
  -e TZ=Asia/Shanghai \
  -e APP_TITLE="QuantumZhou.Identity" \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e Database__Provider=PostgreSQL \
  -e ConnectionStrings__PostgreSQL="Host=ruoyu-postgres;Port=5432;Database=ruoyu_identity;Username=postgres;Password=postgres" \
  -e ADMIN_BOOTSTRAP_USERNAME=admin \
  -e ADMIN_BOOTSTRAP_PASSWORD=YourSecurePassword \
  -e Sms__BypassCode="" \
  -e LOKI_URI=http://ruoyu-loki:3100 \
  -e CONSUL_MODE=On \
  -e CONSUL_HOST=ruoyu-consul \
  -e CONSUL_PORT=8500 \
  -e CONSUL_SERVICE_NAME=QuantumZhou.Identity \
  -v "$(pwd)/data/identity/master-key:/app/master-key" \
  -v "$(pwd)/data/identity/consul:/app/data/consul" \
  "$IMAGE_NAME"
```

## 11. 实施 Checklist

| # | 任务 | 优先级 | 说明 |
|---|------|--------|------|
| C1 | 创建 `ConsulConfigurationProvider.cs` | P0 | 核心：Consul KV → IConfiguration 转换逻辑 |
| C2 | 创建 `LocalConfigCache.cs` | P0 | 本地缓存文件读写 + 原子替换 |
| C3 | 创建 `ConsulServiceRegistrar.cs` | P0 | 启动时注册服务到 Consul Catalog |
| C4 | 创建 `ConsulOptions.cs` 强类型配置 | P1 | 绑定 `Consul:` 配置节 |
| C5 | 修改 `Program.cs` | P0 | 根据 `CONSUL_MODE` 条件调用 C1-C3 |
| C6 | 修改 `appsettings.json` 添加 `Consul:` 节 | P0 | 默认值（Mode=Off） |
| C7 | 新增 `/consul/status` 端点 | P1 | 仅 Consul 模式映射 |
| C8 | 修改 `/health` 端点增加 Consul 连通性检查 | P1 | 不影响独立模式行为 |
| C9 | 修改 `start.sh` | P1 | 条件注入 CONSUL_* 环境变量 |
| C10 | 新增 `data/consul/` 目录挂载 | P0 | 缓存持久化 |
| C11 | 编写 `script/env-script/06-consul/start.sh` | P1 | 参见 `docs/env/consul.md` 第 4.4 节 |
| C12 | 编写 KV 种子脚本 | P2 | 一次性推送初始配置 |
| C13 | 单元测试：ConsulConfigurationProvider | P0 | 测试 KV → 配置节映射、空值、JSON 错误处理 |
| C14 | 单元测试：LocalConfigCache | P0 | 测试原子替换、损坏回放、文件锁 |
| C15 | 集成测试：Consul 模式完整启动流程 | P1 | 需要 Docker Compose 临时环境 |

## 12. 工作量估计

| 阶段 | 任务 | 人天 |
|------|------|------|
| 核心代码 | C1-C5（含测试 C13-C14） | 2.5 |
| 基础设施 | C6-C12 | 1 |
| 集成测试 | C15 | 0.5 |
| 文档 | 本文件 + Configuration.md 更新 | 0.5 |
| **合计** | | **4.5 人天** |

## 13. 参考

- 项目级 Consul 方案：`docs/env/consul.md`（全局编号 ADR-001，Consul 集成决策）
- [Consul KV API](https://developer.hashicorp.com/consul/api-docs/kv)
- [Consul Catalog - Service Registration](https://developer.hashicorp.com/consul/api-docs/catalog#register-entity)
- [Consul Health Checks](https://developer.hashicorp.com/consul/docs/discovery/checks)
- [ASP.NET Core Custom Configuration Provider](https://learn.microsoft.com/en-us/dotnet/core/extensions/custom-configuration-provider)
