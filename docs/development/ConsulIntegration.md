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
| `CONSUL_HOST` | `ruoyu-consul` | 否 | Consul HTTP API 地址 |
| `CONSUL_PORT` | `8500` | 否 | Consul HTTP API 端口 |
| `CONSUL_SERVICE_NAME` | `QuantumZhou.Identity` | 否 | 注册到 Consul 的服务名 |
| `CONSUL_SERVICE_ID` | 自动生成 | 否 | 服务实例 ID（多实例需唯一）|
| `CONSUL_KV_PREFIX` | `config/ruoyu` | 否 | KV 路径前缀 |
| `CONSUL_PROFILE` | 与 `ASPNETCORE_ENVIRONMENT` 一致 | 否 | KV 路径中的环境段 |
| `CONSUL_TIMEOUT_MS` | `3000` | 否 | 请求超时（毫秒） |
| `CONSUL_RETRY_COUNT` | `3` | 否 | 重试次数（指数退避） |
| `CONSUL_ENABLE_CACHE` | `true` | 否 | 是否启用本地缓存降级 |
| `CONSUL_CACHE_DIR` | `./data/consul` | 否 | 缓存文件存放路径 |

> 独立模式下以上所有变量均不生效，即使设置了也忽略。

## 4. 配置分层（Consul 模式）

完整优先级（从高到低）：

```
1. 命令行参数
2. __ 分隔符环境变量（Database__Provider 等）
3. Consul KV（config/ruoyu/QuantumZhou.Identity/{profile}/{key}）
4. 本地缓存文件（Consul 不可达时回退）
5. appsettings.{Environment}.json
6. appsettings.json（最低 — 兜底默认值）
```

> **注意**：Consul KV 优先级高于 appsettings 但低于环境变量。这意味着：
> - 环境变量可以覆盖 Consul KV（调试友好）
> - appsettings 中的默认值始终作为兜底

## 5. 关于密钥存放策略

### 5.1 走 Consul KV（推荐）

所有配置统一放入 Consul KV（含密钥）。理由：

- **全部服务运行在本地 Docker 内网**（`ruoyu-net`），无公网暴露面
- **Consul ACL 控制访问**：匿名 token 无法读取 KV，只有持有正确 token 的客户端可访问
- **env 并不比 Consul 更安全**：`docker inspect`、`ps -p <pid> -E` 都能看到进程环境变量；Consul 至少还需要 ACL token
- **审计与版本追溯**：Consul API 天然支持历史版本对比与回滚，env 改动无痕
- **一致性**：一个平台管所有配置，运维心智负担更低

### 5.2 配合 ACL 使用

| ACL Policy | 权限 | 使用场景 |
|-----------|------|---------|
| 服务 token | 读自己命名空间 + 写自己注册 | 业务服务自身 |
| 部署 token | 全局读写 | CI / 部署脚本 |
| 匿名 token | 无 | 未授权客户端 |

Consul 8500 端口**不暴露公网**，仅映射到宿主机 localhost 用于调试与运维。

### 5.3 何时仍需环境变量

以下场景可继续保留环境变量（而非放入 Consul KV）：

- **CI 流水线注入**（GitLab CI vars / GitHub Actions）—— 这些系统自带加密与审计，不需要再走 Consul
- **紧急情况调试**（`docker run -e FOO=bar` 快速覆盖）

## 6. Consul KV 映射规则

### 6.1 路径格式

```
config/ruoyu/{ServiceName}/{Profile}/
├── serilog.json              → Serilog 完整配置节
├── feature-flags.json        → 功能开关
├── downstream.json           → 下游服务地址
└── grpc-settings.json        → gRPC 全局策略
```

`Profile` = `ASPNETCORE_ENVIRONMENT` 的小写（`Production` → `prod`）。

### 6.2 KV → IConfiguration 映射

Consul KV Value 必须是 JSON 字符串。Steeltoe `AddConsul()` 会自动将 KV 的 key（不含 prefix）映射为 `:` 分隔的配置层级。

| Consul KV 路径 | IConfiguration Key |
|---------------|--------------------|
| `config/ruoyu/QuantumZhou.Identity/prod/serilog.json` | `Serilog:*` |
| `config/ruoyu/_global/feature-flags.json` | `FeatureFlags:*` |

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
> **当前阶段范围**：仅实现服务发现。KV 配置加载降级为"未来扩展点"：
> - `ConsulCacheService` 类完整实现（原子写入 + 损坏处理）作为占位
> - `ProgramConsulExtensions.AddConsulIfEnabled` 仅从缓存加载（未来 KV 包发布后在此插入 `AddConsul()`）
> - `SaveConsulCacheIfEnabled` 暂为 no-op（无 KV 加载源，没有数据可缓存）
> - 独立模式（CONSUL_MODE=Off）行为与改造前完全一致

### 8.2 新增文件

| 文件 | 作用 | 行数估算 |
|------|------|---------|
| `Host/Configuration/ConsulCacheService.cs` | 本地缓存读写（原子替换 + 损坏回放）| ~80 |
| `Host/Configuration/ProgramConsulExtensions.cs` | 扩展方法：封装 Steeltoe 调用 + 降级逻辑 | ~60 |
| `Host/Configuration/ConsulOptions.cs` | 强类型配置类（绑定 appsettings.json `Consul:` 节）| ~20 |
| `config/consul/server.json` | Consul Agent 配置文件 | ~10 |

> 总计新增 ~170 行自建代码，其余由 Steeltoe 处理。

### 8.3 Program.cs 改造点

```csharp
// 现有代码不变...
var builder = WebApplication.CreateBuilder(args);

// 新增：Consul 配置注册（根据 CONSUL_MODE 条件启用）
builder.Configuration.AddConsulIfEnabled(builder.Configuration);
builder.Services.AddConsulDiscoveryIfEnabled(builder.configuration);
```

### 8.4 扩展方法核心逻辑

> **当前阶段**：`Steeltoe.Configuration.Consul` 包不存在，`AddConsulIfEnabled` 仅从本地缓存加载（占位）。
> 未来 Steeltoe 发布 KV 配置包后，在 `try` 块中插入 `builder.AddConsul(...)` 即可启用 KV 加载。

```csharp
public static class ProgramConsulExtensions
{
    public static IConfigurationBuilder AddConsulIfEnabled(this IConfigurationBuilder builder, IConfiguration config)
    {
        if (!ConsulOptions.IsEnabled(config)) return builder;

        var opts = ConsulOptions.Bind(config);
        var cacheService = new ConsulCacheService(opts.CacheDirectory);

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
                    // 日志：使用本地缓存启动（Consul KV 加载暂未实现）
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

Consul 模式正常时新增管理端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/consul/status` | GET | Consul 连接状态 / 最后成功时间 / 缓存年龄 |
| `/consul/cache/invalidate` | POST | 强制清空本地缓存（下次启动重新拉取）|

> `/health` 端点**始终映射**，Consul 模式正常时额外包含 Consul 连通性信息。

## 10. 健康检查

- **独立模式**：与现状一致（仅数据库检查）
- **Consul 模式（正常）**：数据库 + Consul 连通性
- **Consul 模式（降级）**：数据库 + 降级告警

```json
// Consul 模式正常
{ "status": "Healthy", "results": [
  { "name": "database", "status": "Healthy" },
  { "name": "consul", "status": "Healthy", "description": "Connected to ruoyu-consul:8500" }
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
CONSUL_HOST="${CONSUL_HOST:-ruoyu-consul}"
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

# 服务级配置
consul kv put config/ruoyu/QuantumZhou.Identity/prod/serilog.json '{"MinimumLevel":{"Default":"Information"}}'
consul kv put config/ruoyu/_global/feature-flags.json '{"EnableNewLogin":true}'

# 如有密钥（也可通过 CI/部署脚本一次性注入）
# consul kv put config/ruoyu/QuantumZhou.Identity/prod/db-connection.json '...'
```

> 首次部署后沉淀为 `script/env-script/06-consul/seed-identity-kv.sh` 脚本复用。

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
  -e Database__Provider=PostgreSQL \
  -e ConnectionStrings__PostgreSQL="Host=ruoyu-postgres;Port=5432;Database=ruoyu_identity;Username=postgres" \
  -e CONSUL_MODE=On \
  -e CONSUL_HOST=ruoyu-consul \
  -e CONSUL_PORT=8500 \
  -e CONSUL_SERVICE_NAME=QuantumZhou.Identity \
  -v "$(pwd)/data/identity/master-key:/app/master-key" \
  -v "$(pwd)/data/identity/consul:/app/data/consul" \
  "$IMAGE_NAME"
```

## 13. 实施 Checklist

| # | 任务 | 优先级 | 当前状态 |
|---|------|--------|---------|
| C1 | 创建 `ConsulCacheService.cs`（本地缓存读写 + 原子替换）| P0 | ✅ 已实现（占位，等 KV 加载启用后写入缓存） |
| C2 | 创建 `ConsulOptions.cs`（强类型配置类）| P0 | ✅ 已实现 |
| C3 | 创建 `ProgramConsulExtensions.cs`（封装 Steeltoe + 降级逻辑）| P0 | ✅ 已实现（AddConsulIfEnabled 仅缓存加载，AddConsulDiscoveryIfEnabled 调用 Steeltoe） |
| C4 | 修改 `Program.cs` 调用 C3 | P0 | ✅ 已实现 |
| C5 | 在 `csproj` 引入 Steeltoe.Discovery.Consul 4.2.0 | P0 | ✅ 已实现（~~Steeltoe.Configuration.Consul~~ 包不存在） |
| C6 | 修改 `appsettings.json` 添加 `Consul:` 配置节（Mode=Off 默认值）| P0 | ✅ 已实现 |
| C7 | 新增 `/consul/status` 和 `/consul/cache/invalidate` 端点 | P1 | ⏸ 暂缓（未来 task） |
| C8 | `/health` 端点增加 Consul 连通性检查 | P1 | ⏸ 暂缓（未来 task） |
| C9 | 修改 `start.sh` 条件注入 CONSUL_* 环境变量 | P1 | ✅ 已实现 |
| C10 | 新增 `data/consul/` 目录挂载 | P0 | ✅ 已实现 |
| C11 | 单元测试：ConsulCacheService（原子替换 / 损坏回放）| P0 | ⏸ 暂缓（未来 task，当前阶段缓存为占位） |
| C12 | 集成测试：Consul 模式完整启动 + 降级切换 | P1 | ⏸ 暂缓（未来 task） |
| C13 | 编写 Consul KV 种子脚本 | P2 | ✅ 已实现（`script/env-script/06-consul/seed-identity-kv.sh`） |

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
