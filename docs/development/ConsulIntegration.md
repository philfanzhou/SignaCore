# Consul 服务发现 + 配置中心集成

> 目标：引入 Consul 作为基础设施组件（与 Loki / PostgreSQL 同级），集中管理配置与服务注册，同时保留完全独立的本地运行能力。

## 状态

- **决策**：已接受（2026-07-11），参见 `docs/env/consul.md`
- **实施状态**：决策已接受，待实施
- **负责人**：待分配

## 1. 三种运行模式

Identity 支持三种模式，由环境变量 `CONSUL_MODE` 控制：

| 模式 | `CONSUL_MODE` | 说明 |
|------|--------------|------|
| **独立模式（默认）** | `Off`（或不设置）| 完全自给自足，按原机制加载；不发起任何 Consul 调用 |
| **Consul 模式** | `On` | 启动时从 Consul KV 加载配置、注册服务、开启健康检查；Consul 不可达时降级到本地缓存 |
| **本地缓存回退** | `On` 但 Consul 不可达 | 使用上一次成功拉取的缓存文件启动；日志告警但不阻断 |

> **原则**：独立模式永远是默认且可用的。Consul 是"增强"而非"必需"。

## 2. 启动时序

### 2.1 独立模式（CONSUL_MODE=Off 或不设置）

```
容器启动 → WebApplication.CreateBuilder 加载 appsettings.json → appsettings.{env}.json
→ 环境变量（__ 分隔符）覆盖 → 原有启动流程 → 对外服务
```

与改造前完全一致，无任何新增代码路径或网络调用。

### 2.2 Consul 模式（CONSUL_MODE=On）

```
容器启动 → 加载 appsettings.json（Layer 0 兜底）
→ 尝试连接 Consul（地址来自 CONSUL_HOST 环境变量）
│
├── 成功
│   → Steeltoe AddConsul() 从 Consul KV 加载配置 → 合并到 IConfiguration
│   → 生成本地缓存文件 data/consul/cache.json（供下次降级兜底）
│   → Steeltoe AddConsulDiscovery() 注册服务 + HTTP 健康检查 /health
│   → 启动原有流程 → 对外服务
│
└── 失败（Consul 不可达 / 超时）
    → 读取 data/consul/cache.json
    │   ├── 缓存存在且有效 → 使用缓存启动（降级，不注册服务）+ 告警
    │   └── 缓存不存在 → 使用 appsettings.json 默认值启动 + 告警
```

### 2.3 三种模式对比

| 维度 | 独立模式 | Consul 正常 | Consul 降级 |
|------|---------|------------|------------|
| Consul 网络调用 | 0 次 | 启动时 N+1 次 | 0 次（快速失败） |
| 配置来源 | appsettings + env | Consul KV（优先）+ appsettings（兜底） | 本地缓存 + appsettings |
| 服务注册到 Consul | ❌ | ✅ | ❌ |
| 对服务可用性影响 | 无 | 无 | 无 |

## 3. 环境变量

| 变量 | 默认值 | 必需 | 说明 |
|------|--------|------|------|
| `CONSUL_MODE` | `Off` | 否 | `Off` = 独立；`On` = 启用 Consul |
| `CONSUL_HOST` | `host.docker.internal` | 否 | Consul HTTP API 地址 |
| `CONSUL_PORT` | `8500` | 否 | Consul HTTP API 端口 |
| `CONSUL_SERVICE_NAME` | `QuantumZhou.Identity` | 否 | 注册到 Consul 的服务名 |
| `CONSUL_SERVICE_ID` | 自动生成 | 否 | 服务实例 ID（多实例需唯一）|
| `CONSUL_KV_PREFIX` | `config/ruoyu` | 否 | KV 路径前缀 |
| `CONSUL_PROFILE` | 与 `ASPNETCORE_ENVIRONMENT` 一致 | 否 | KV 路径中的环境段 |
| `CONSUL_TIMEOUT_MS` | `3000` | 否 | 请求超时（毫秒） |
| `CONSUL_RETRY_COUNT` | `3` | 否 | 重试次数（指数退避） |
| `CONSUL_ENABLE_CACHE` | `true` | 否 | 是否启用本地缓存降级 |
| `CONSUL_CACHE_DIR` | `./data/consul` | 否 | 缓存文件存放路径 |
| `CONSUL_TOKEN` | （空） | 否 | Consul ACL token（启用 ACL 时必需）。`ConsulOptions.Bind()` 读取后注入到 `Consul:Token` 配置节，Steeltoe 客户端自动绑定使用 |

> 独立模式下以上所有变量均不生效，即使设置了也忽略。
>
> **ACL token 说明**：当 Consul 集群启用 ACL（`acl.enabled=true`）时，必须设置 `CONSUL_TOKEN` 环境变量，
> 值为 `script/env-script/06-consul/config/server.json` 中的 `acl.tokens.agent`。
> 未设置时 Steeltoe 客户端将无法通过 ACL 验证，Consul API 调用返回 403。

## 4. 配置分层（Consul 模式）

完整优先级（从高到低）：

```
1. 命令行参数
2. __ 分隔符环境变量（Database__Provider 等）
3. Consul KV（按 `_global` → `_shared/{profile}` → `QuantumZhou.Identity/{profile}` 顺序合并）
4. 本地缓存文件（Consul 不可达时回退）
5. appsettings.{Environment}.json
6. appsettings.json（最低 — 兜底默认值）
```

> **注意**：Consul KV 优先级高于 appsettings 但低于环境变量。这意味着：
> - 环境变量可以覆盖 Consul KV（调试友好）
> - appsettings 中的默认值始终作为兜底

## 5. 关于密钥存放策略

### 5.1 走 Consul KV（推荐）

非密钥配置优先放入 Consul KV。理由：

- **业务服务运行在本地 Docker 内网**（如 `ruoyu-net`），Consul 通过宿主机 `8500` 端口暴露给容器访问
- **Consul ACL 控制访问**：匿名 token 无法读取 KV，只有持有正确 token 的客户端可访问
- **env 并不比 Consul 更安全**：`docker inspect`、`ps -p <pid> -E` 都能看到进程环境变量；Consul 至少还需要 ACL token
- **审计与版本追溯**：Consul API 天然支持历史版本对比与回滚，env 改动无痕
- **一致性**：一个平台管所有非密钥配置，运维心智负担更低

### 5.2 配合 ACL 使用

| ACL Policy | 权限 | 使用场景 |
|-----------|------|---------|
| 服务 token | 读自己命名空间 + 写自己注册 | 业务服务自身 |
| 部署 token | 全局读写 | CI / 部署脚本 |
| 匿名 token | 无 | 未授权客户端 |

Consul 8500 端口**不暴露公网**，仅映射到宿主机 localhost 用于调试与运维。

### 5.3 何时仍需环境变量

以下场景继续保留环境变量（而非放入 Consul KV）：

- **CI 流水线注入**（GitLab CI vars / GitHub Actions）—— 这些系统自带加密与审计，不需要再走 Consul
- **紧急情况调试**（`docker run -e FOO=bar` 快速覆盖）
- **密钥/密码**（如 `DB_PASSWORD`、`RSA_MASTER_KEY`、AppSecret）—— 继续保留在环境变量

## 6. Consul KV 映射规则

### 6.1 路径格式

```
config/ruoyu/
├── _global/
│   ├── serilog.json          → 全局日志最小级别 / Override
│   └── feature-flags.json    → 全局功能开关
├── _shared/{Profile}/
│   ├── infrastructure.json    → 共享基础设施地址（PostgreSql/Loki 等非密钥）
│   └── service-endpoints.json → 跨服务共享入口地址 / Audience / RequireHttpsMetadata
└── {ServiceName}/{Profile}/
    └── *.json                → 仅该服务自身生效的专属策略
```

`Profile` = `ASPNETCORE_ENVIRONMENT` 的小写（`Production` → `prod`）。

### 6.2 KV → IConfiguration 映射

Consul KV Value 必须是 JSON 字符串，且文件内容直接保存真实配置根对象。Identity 的自研 KV Loader 会把 JSON 根对象递归展开为 `:` 分隔的配置键。

| Consul KV 路径 | IConfiguration Key |
|---------------|--------------------|
| `config/ruoyu/_global/serilog.json` | `Serilog:*` |
| `config/ruoyu/_global/feature-flags.json` | `FeatureFlags:*` |
| `config/ruoyu/_shared/prod/infrastructure.json` | `Loki:*` / `PostgreSql:*` |
| `config/ruoyu/_shared/prod/service-endpoints.json` | `IdentityService:*` / 其他共享入口配置 |

## 7. 本地缓存机制

> 这是独立于 Steeltoe 的部分——Steeltoe 本身**不提供**Consul 不可达时的降级缓存。需要在 Steeltoe 外层包装。

### 7.1 时机

- **写入**：每次成功从 Consul 拉取配置后，把完整配置快照写入本地 `cache.json`
- **读取**：Consul 连接失败时，作为兜底加载本地缓存
- **不主动过期**：仅在"Consul 不可达时"被动使用

### 7.2 存储位置

```
data/
└── consul/
    ├── cache.json              ← 最后成功获取的配置快照（原子写入）
    └── cache.metadata.json     ← 元数据的获取时间 / Consul 地址 / 版本号
```

### 7.3 原子替换

先写 `cache.json.tmp`，再 `rename` 为 `cache.json`，防止写入过程中断导致缓存损坏。

### 7.4 损坏处置

如果 `cache.json` 损坏或 JSON 解析失败，跳过缓存、直接用本地 appsettings 启动（`LogCritical` 级别日志）。

## 8. 代码结构

### 8.1 NuGet 依赖

| 包名 | 作用 | 新增 | 当前状态 |
|------|------|------|---------|
| ~~`Steeltoe.Configuration.Consul`~~ | 从 Consul KV 加载配置到 `IConfiguration` | ✅ 计划新增 | ❌ NuGet 包不存在（Steeltoe 4.x 未提供 Consul KV 配置加载） |
| `Steeltoe.Discovery.Consul` (4.2.0) | 服务注册 + 客户端服务发现 | ✅ 新增 | ✅ 当前阶段唯一可用包 |

> 不引入 Steeltoe 全套（Actuator/Endpoint/Management 等），只引最小必需包。
>
> **当前阶段范围**：
> - `Steeltoe.Discovery.Consul` 负责服务注册
> - Identity 使用自研 HTTP KV Loader 拉取 `_global/_shared/service` 三层配置
> - `ConsulCacheService` 负责成功拉取后的本地缓存和失败回退
> - 独立模式（CONSUL_MODE=Off）行为与改造前完全一致

### 8.2 新增文件

| 文件 | 作用 | 行数估算 |
|------|------|---------|
| `Host/Configuration/ConsulCacheService.cs` | 本地缓存读写（原子替换 + 损坏回放）| ~80 |
| `Host/Configuration/ConsulKvLoader.cs` | 调用 Consul KV API，拉取并展开 JSON 快照 | ~160 |
| `Host/Configuration/ProgramConsulExtensions.cs` | 扩展方法：封装 KV 加载、缓存回退、ACL token 注入、Steeltoe Discovery | ~140 |
| `Host/Configuration/ConsulOptions.cs` | 强类型配置类（绑定 appsettings.json `Consul:` 节，含 `Token` 属性）| ~120 |
| `config/server.json` | Consul Agent 配置文件（人工填写 ACL token）| ~20 |

> 总计新增 ~300 行自建代码，其余由 Steeltoe 处理。

### 8.3 Program.cs 改造点

```csharp
// 现有代码不变...
var builder = WebApplication.CreateBuilder(args);

// 新增：Consul 配置注册（根据 CONSUL_MODE 条件启用）
builder.Configuration.AddConsulIfEnabled(builder.Configuration);
builder.Services.AddConsulDiscoveryIfEnabled(builder.configuration);
```

### 8.4 扩展方法核心逻辑

> **当前阶段**：`Steeltoe.Configuration.Consul` 包不存在，因此直接使用 Consul HTTP KV API 拉取配置，并在失败时回退本地缓存。

```csharp
public static class ProgramConsulExtensions
{
    public static IConfigurationBuilder AddConsulIfEnabled(this IConfigurationBuilder builder, IConfiguration config)
    {
        if (!ConsulOptions.IsEnabled(config)) return builder;

        var opts = ConsulOptions.Bind(config);

        // ACL token 注入：把 CONSUL_TOKEN 环境变量值注入到 "Consul:Token" 配置节，
        // 供 Steeltoe 内置 ConsulOptions 读取（Steeltoe 的 AddConsulDiscoveryClient 不接受配置回调）。
        if (!string.IsNullOrEmpty(opts.Token))
        {
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Consul:Token"] = opts.Token
            });
        }

        var cacheService = new ConsulCacheService(opts.CacheDirectory, logger: null);

        // 【未来扩展点】Steeltoe.Configuration.Consul 包发布后，此处插入：
        // try { builder.AddConsul(c => { c.Host = opts.Host; ... c.FailFast = false; }); }
        // catch (Exception ex) { /* 降级到缓存 */ }

        // 当前阶段：直接尝试从本地缓存加载（如果存在）
        if (opts.EnableCache)
        {
            try
            {
                var cached = cacheService.Load();
                if (cached != null)
                {
                    builder.AddInMemoryCollection(cached);
                }
            }
            catch (Exception)
            {
                // 缓存损坏 → 跳过，用 appsettings 启动
            }
        }

        return builder;
    }

    public static IServiceCollection AddConsulDiscoveryIfEnabled(this IServiceCollection services, IConfiguration config)
    {
        if (!ConsulOptions.IsEnabled(config)) return services;

        // Steeltoe.Discovery.Consul 4.2.0：注册 Consul 服务发现客户端
        // ConsulDiscoveryOptions 绑定 "Consul:Discovery:" 节（Host/Port/ServiceName/HealthCheckPath 等）
        // ConsulOptions（Steeltoe 内置）绑定 "Consul:" 节（Host/Port/Scheme/Token）
        // ACL token 已在 AddConsulIfEnabled 阶段通过 AddInMemoryCollection 注入到 "Consul:Token"
        services.AddConsulDiscoveryClient();

        return services;
    }
}
```

> **Steeltoe 4.2.0 API 说明**：
> - 入口方法：`AddConsulDiscoveryClient(IServiceCollection)`（命名空间 `Steeltoe.Discovery.Consul`）
> - 配置类：`ConsulDiscoveryOptions`（绑定 `Consul:Discovery:` 节，含 ServiceName/InstanceId/HealthCheckPath 等）
> - 配置类：`ConsulOptions`（Steeltoe 内置，绑定 `Consul:` 节，含 Host/Port/Scheme/Token）
> - **不包含** `AddConsul` 配置加载扩展方法（KV 配置加载未实现）

## 9. 服务端点

Consul 模式新增管理端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/consul/status` | GET | Consul 连接状态 / 最后成功时间 / 缓存年龄 |
| `/consul/cache/invalidate` | POST | 强制清空本地缓存（下次启动重新拉取）|

> `/health` 端点**始终映射**。当前阶段仍以数据库健康检查为主，Consul 连接状态通过 `/consul/status` 单独查看。

## 10. 健康检查

- **独立模式**：与现状一致（仅数据库检查）
- **Consul 模式（正常）**：数据库 + Consul 连通性
- **Consul 模式（降级）**：数据库 + 降级告警

```json
// Consul 模式正常
{ "status": "Healthy", "results": [
  { "name": "database", "status": "Healthy" },
  { "name": "consul", "status": "Healthy", "description": "Connected to host.docker.internal:8500" }
]}

// Consul 模式降级
{ "status": "Healthy", "results": [
  { "name": "database", "status": "Healthy" },
  { "name": "consul", "status": "Degraded", "description": "Using local cache" }
]}
```

## 11. start.sh 改造

```bash
# Consul（可选，不设置=保持独立模式）
CONSUL_MODE="${CONSUL_MODE:-Off}"
CONSUL_HOST="${CONSUL_HOST:-host.docker.internal}"
CONSUL_PORT="${CONSUL_PORT:-8500}"
CONSUL_SERVICE_NAME="${CONSUL_SERVICE_NAME:-QuantumZhou.Identity}"

if [ "$CONSUL_MODE" = "On" ]; then
  CONSUL_ENV=" \
    -e CONSUL_MODE=On \
    -e CONSUL_HOST=${CONSUL_HOST} \
    -e CONSUL_PORT=${CONSUL_PORT} \
    -e CONSUL_SERVICE_NAME=${CONSUL_SERVICE_NAME} \
    -e CONSUL_KV_PREFIX=config/ruoyu"
else
  CONSUL_ENV=""
fi

docker run -d \
  ...原有参数... \
  ${CONSUL_ENV} \
  "$IMAGE_NAME"
```

## 12. 部署流程

### 12.1 Consul 容器先行启动

```bash
script/env-script/06-consul/start.sh    # 新建
```

### 12.2 推送初始配置到 Consul（一次性）

```bash
CONSUL_HTTP_ADDR=http://localhost:8500

# 启动 Consul 并自动导入版本化 KV 文件
./script/env-script/06-consul/start.sh

# 推荐维护的共享配置：
# - script/env-script/06-consul/config/kv/_shared__prod__infrastructure.json
# - script/env-script/06-consul/config/kv/_shared__prod__service-endpoints.json
```

> 首次部署后沉淀为 `script/env-script/06-consul/start.sh` 统一复用，业务配置内容保存在 `script/env-script/06-consul/config/kv/`，采用扁平文件名编码目标 key。

### 12.3 Identity 容器启动（Consul 模式）

```bash
docker run -d \
  --name ruoyu-identity \
  --restart unless-stopped \
  --network ruoyu-net \
  -p 10891:5002 \
  -e TZ=Asia/Shanghai \
  -e APP_TITLE="QuantumZhou.Identity" \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e CONSUL_MODE=On \
  -e CONSUL_HOST=host.docker.internal \
  -e CONSUL_PORT=8500 \
  -e CONSUL_SERVICE_NAME=QuantumZhou.Identity \
  -e CONSUL_TOKEN="<acl-token>" \
  -e DB_PASSWORD="<postgres-password>" \
  -v "$(pwd)/data/identity/master-key:/app/master-key" \
  -v "$(pwd)/data/identity/consul:/app/data/consul" \
  "$IMAGE_NAME"
```

## 13. 实施 Checklist

| # | 任务 | 优先级 | 当前状态 |
|---|------|--------|---------|
| C1 | 创建 `ConsulCacheService.cs`（本地缓存读写 + 原子替换）| P0 | ✅ 已实现 |
| C2 | 创建 `ConsulOptions.cs`（强类型配置类）| P0 | ✅ 已实现 |
| C3 | 创建 `ProgramConsulExtensions.cs`（封装 KV 加载 + 缓存回退 + Steeltoe）| P0 | ✅ 已实现 |
| C3.1 | 创建 `ConsulKvLoader.cs`（HTTP 拉取 `_global/_shared/service` 三层）| P0 | ✅ 已实现 |
| C4 | 修改 `Program.cs` 调用 C3 | P0 | ✅ 已实现 |
| C5 | 在 `csproj` 引入 Steeltoe.Discovery.Consul 4.2.0 | P0 | ✅ 已实现（~~Steeltoe.Configuration.Consul~~ 包不存在） |
| C6 | 修改 `appsettings.json` 添加 `Consul:` 配置节（Mode=Off 默认值）| P0 | ✅ 已实现 |
| C7 | 新增 `/consul/status` 和 `/consul/cache/invalidate` 端点 | P1 | 本轮补齐 |
| C8 | `/health` 端点增加 Consul 连通性检查 | P1 | 当前仍暂缓 |
| C9 | 修改 `start.sh` 条件注入 CONSUL_* 环境变量 | P1 | ✅ 已实现 |
| C10 | 新增 `data/consul/` 目录挂载 | P0 | ✅ 已实现 |
| C11 | 单元测试：Consul KV Loader / CacheService | P0 | 本轮补齐最小覆盖 |
| C12 | 集成测试：Consul 模式完整启动 + 降级切换 | P1 | ⏸ 暂缓（未来 task） |
| C13 | 编写 Consul KV 导入逻辑 | P2 | ✅ 已实现（`script/env-script/06-consul/start.sh` 内置导入 + `config/kv/` 扁平文件） |

## 14. 工作量估计

| 阶段 | 任务 | 人天 |
|------|------|------|
| 核心代码 | C1-C5（含测试 C11）| 1.5 |
| 端点+健康检查 | C6-C10 | 0.5 |
| 集成测试 | C12 | 0.5 |
| 文档 | 本文件 + 同步维护 | 0.3 |
| **合计** | | **~2.8 人天** |

## 15. 参考

- 项目级 Consul 方案：`docs/env/consul.md`（ADR-001）
- [Steeltoe Configuration Consul Docs](https://docs.steeltoe.io/api/v3/configuration/hashicorp-consul-configuration-source.html)
- [Steeltoe Discovery Consul Docs](https://docs.steeltoe.io/api/v3/discovery/hashicorp-consul-discovery.html)
- [Consul KV API](https://developer.hashicorp.com/consul/api-docs/kv)
- [ASP.NET Core Custom Configuration Provider](https://learn.microsoft.com/en-us/dotnet/core/extensions/custom-configuration-provider)（参考 Steeltoe 降级缓存实现）
