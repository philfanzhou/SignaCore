# Consul 服务发现 + 配置中心集成

> 目标：引入 Consul 作为基础设施组件（与 Loki / PostgreSQL 同级），集中管理配置与服务注册，并把 Identity 部署脚本收敛为必须由 Consul 提供运行配置。

## 状态

- **决策**：已接受（2026-07-11），参见 `docs/env/consul.md`
- **实施状态**：决策已接受，待实施
- **负责人**：待分配

## 1. 启动约束

Identity 的项目级部署脚本 `start.sh` 固定接入 Consul，不再维护任何启停开关。

当前运行态只有两种：

| 运行态 | 条件 | 说明 |
|------|------|------|
| **Consul 正常** | Consul 可达 | 启动时从 Consul KV 加载配置、注册服务、开启健康检查 |
| **本地缓存回退** | Consul 不可达 | 使用上一次成功拉取的缓存文件启动；日志告警但不阻断 |

> **原则**：Consul 只承载跨项目共享配置；Identity 的项目独有配置必须保留在 `start.sh`、项目自身配置或程序默认值中。当前 `start.sh` 只把共享的数据库地址/密码和 Loki 地址交给 Consul，`Database:Provider` 使用程序默认值，`Database:Name` 如需覆盖再回到项目脚本。

## 2. 启动时序

```
容器启动 → 加载 appsettings.json（Layer 0 兜底）
→ 尝试连接 Consul（地址来自 CONSUL_HTTP_ADDR）
│
├── 成功
│   → 自研 HTTP KV Loader 按 `config/ruoyu/*` 拉取共享配置
│   → 生成本地缓存文件 data/consul/cache.json（供下次回退）
│   → Steeltoe AddConsulDiscovery() 注册服务 + HTTP 健康检查 /health
│   → 启动原有流程 → 对外服务
│
└── 失败（Consul 不可达 / 超时）
    → 读取 data/consul/cache.json
    │   ├── 缓存存在且有效 → 使用缓存启动（降级，不注册服务）+ 告警
    │   └── 缓存不存在 → 使用 appsettings.json 默认值启动 + 告警
```

### 2.1 启动诊断日志

为便于排查“到底有没有拿到 Consul 配置”这类问题，Identity 启动阶段必须输出两类诊断日志：

- **Consul 拉取过程日志**：在真正访问 Consul KV 前后记录目标地址、KV 前缀、超时、重试次数、是否携带 token，以及最终结果是 `Consul`、`Cache` 还是 `AppSettings`
- **最终生效配置摘要**：在应用构建完成后记录关键配置的最终值摘要，至少包含 `PostgreSql:Host`、`PostgreSql:Port`、`PostgreSql:Username`、`Database:Name`、`Loki:Uri`、Consul 当前来源
- **敏感字段脱敏**：`CONSUL_TOKEN`、`PostgreSql:Password`、AppSecret 等敏感值禁止完整写入日志；只允许输出脱敏摘要
- **失败场景可见**：当 Consul 加载失败且回退到缓存或 `appsettings.json` 时，日志必须明确写出失败原因和当前回退来源，避免仅凭异常堆栈猜测

## 3. 环境变量

| 变量 | 默认值 | 必需 | 说明 |
|------|--------|------|------|
| `CONSUL_HTTP_ADDR` | `host.docker.internal:8500` | 否 | Consul HTTP API 地址，运行时拆成 Host / Port |
| `CONSUL_SERVICE_NAME` | `QuantumZhou.Identity` | 否 | 注册到 Consul 的服务名；通常使用应用默认值，无需在 `start.sh` 中重复注入 |
| `CONSUL_SERVICE_ID` | 自动生成 | 否 | 服务实例 ID（多实例需唯一）|
| `CONSUL_KV_PREFIX` | `config/ruoyu` | 否 | KV 路径前缀 |
| `CONSUL_TIMEOUT_MS` | `3000` | 否 | 请求超时（毫秒） |
| `CONSUL_RETRY_COUNT` | `3` | 否 | 重试次数（指数退避） |
| `CONSUL_ENABLE_CACHE` | `true` | 否 | 是否启用本地缓存降级 |
| `CONSUL_CACHE_DIR` | `./data/consul` | 否 | 缓存文件存放路径 |
| `CONSUL_TOKEN` | （空） | 是（启用 ACL 时） | Consul ACL token。必须由部署侧显式传入，Identity `start.sh` 不读取 Consul 的 `server.json` |
>
> **ACL token 说明**：当 Consul 集群启用 ACL（`acl.enabled=true`）时，必须由部署侧显式设置 `CONSUL_TOKEN` 环境变量。
> Identity 服务不应读取 `script/env-script/06-consul/config/server.json`，因为那是 Consul Agent 自身的启动配置，不属于业务服务职责边界。
> 未设置时 Steeltoe 客户端将无法通过 ACL 验证，Consul API 调用返回 403。
>
> **宿主机别名说明**：当 `CONSUL_HTTP_ADDR` 使用 `host.docker.internal:*` 时，Docker 启动命令必须补 `--add-host=host.docker.internal:host-gateway`。这样在 Linux Docker 下也能把该别名解析到宿主机网关；Mac/Windows Docker Desktop 也可兼容保留这条参数。

## 4. 配置分层（Consul 模式）

完整优先级（从高到低）：

```
1. 命令行参数
2. 环境变量
3. Consul KV（按 `config/ruoyu/*` 提供共享配置）
4. 本地缓存文件（Consul 不可达时回退）
5. appsettings.{Environment}.json
6. appsettings.json（最低 — 兜底默认值）
```

> **注意**：Consul KV 优先级高于 appsettings，但低于环境变量。当前 `start.sh` 只保留 Consul 连接参数和少数启动密钥类环境变量，不再承担业务配置注入。

> **诊断要求**：启动日志必须能让人直接看出当前 PostgreSQL/Loki 等关键配置究竟来自 Consul、缓存还是 `appsettings.json`；排查时不依赖人工猜测。

## 5. 配置入 KV 策略

### 5.1 走 Consul KV

Identity 当前只把以下共享运行配置放入 Consul KV：

- `config/ruoyu/serilog.json`：统一日志级别
- `config/ruoyu/shared.json`：`Loki:Uri`、`PostgreSql:Host/Port/Username/Password`
- `config/ruoyu/service-endpoints.json`：共享服务入口

这样做的直接结果是：Identity 的共享基础设施参数从 Consul 拉取，而项目独有配置留在项目本地配置或程序默认值中，不再把服务私有配置塞进 Consul。

### 5.2 配合 ACL 使用

| ACL Policy | 权限 | 使用场景 |
|-----------|------|---------|
| 服务 token | 读自己命名空间 + 写自己注册 | 业务服务自身 |
| 部署 token | 全局读写 | CI / 部署脚本 |
| 匿名 token | 无 | 未授权客户端 |

Consul 8500 端口**不暴露公网**，仅映射到宿主机 localhost 用于调试与运维。

### 5.3 仍保留环境变量 / 文件的项

以下配置暂不迁入 Consul KV：

- `RSA_MASTER_KEY`
- `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD`
- `CONSUL_TOKEN`

> 应用预置通过挂载 `data/bootstrap-apps.json` 文件实现，不再通过环境变量注入业务凭据。详见 [Configuration.md](./Configuration.md) "Bootstrap Apps 配置"章节。

## 6. Consul KV 映射规则

### 6.1 路径格式

```
config/ruoyu/
├── serilog.json            → 统一日志最小级别 / Override
├── shared.json             → 共享基础设施地址（PostgreSql/Loki 等）
└── service-endpoints.json  → 跨服务共享入口地址 / Audience / RequireHttpsMetadata
```

### 6.2 KV → IConfiguration 映射

Consul KV Value 必须是 JSON 字符串，且文件内容直接保存真实配置根对象。Identity 的自研 KV Loader 会把 JSON 根对象递归展开为 `:` 分隔的配置键。
为保证 `script/env-script/06-consul/config/kv/*.json` 具备人工可读性，允许使用保留字段 `__comment` 写注释；Loader 会忽略该字段，不把它写进 `IConfiguration`。

| Consul KV 路径 | IConfiguration Key |
|---------------|--------------------|
| `config/ruoyu/serilog.json` | `Serilog:*` |
| `config/ruoyu/shared.json` | `Loki:*` / `PostgreSql:*`（含 `PostgreSql:Password`） |
| `config/ruoyu/service-endpoints.json` | `IdentityService:*` / 其他共享入口配置 |

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
> - Identity 使用自研 HTTP KV Loader 拉取 `config/ruoyu/*` 共享配置
> - `ConsulCacheService` 负责成功拉取后的本地缓存和失败回退
> - 项目级 `start.sh` 固定接入 Consul，但只保留最少注入项

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

// 新增：Consul 配置注册（固定启用）
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

Consul 集成新增管理端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/consul/status` | GET | Consul 连接状态 / 最后成功时间 / 缓存年龄 |
| `/consul/cache/invalidate` | POST | 强制清空本地缓存（下次启动重新拉取）|

> `/health` 端点**始终映射**。当前阶段仍以数据库健康检查为主，Consul 连接状态通过 `/consul/status` 单独查看。

## 10. 健康检查

- **Consul 正常**：数据库 + Consul 连通性
- **Consul 降级**：数据库 + 降级告警

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
CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR:-host.docker.internal:8500}"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"

docker run -d \
  ...原有参数... \
  --add-host=host.docker.internal:host-gateway \
  -e Database__Name=quantumzhou_identity \
  -e CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" \
  -e CONSUL_TOKEN="${CONSUL_TOKEN}" \
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
# - script/env-script/06-consul/config/kv/shared.json
# - script/env-script/06-consul/config/kv/service-endpoints.json
```

> 首次部署后沉淀为 `script/env-script/06-consul/start.sh` 统一复用，业务配置内容保存在 `script/env-script/06-consul/config/kv/`，采用扁平文件名编码目标 key。

### 12.3 Identity 容器启动

```bash
docker run -d \
  --name ruoyu-identity \
  --restart unless-stopped \
  --network ruoyu-net \
  --add-host=host.docker.internal:host-gateway \
  -p 10891:5002 \
  -e TZ=Asia/Shanghai \
  -e APP_TITLE="QuantumZhou.Identity" \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e Database__Name=quantumzhou_identity \
  -e CONSUL_HTTP_ADDR=host.docker.internal:8500 \
  -e CONSUL_TOKEN="<acl-token>" \
  -v "$(pwd)/data/identity:/app/data" \
  "$IMAGE_NAME"
```

## 13. 实施 Checklist

| # | 任务 | 优先级 | 当前状态 |
|---|------|--------|---------|
| C1 | 创建 `ConsulCacheService.cs`（本地缓存读写 + 原子替换）| P0 | ✅ 已实现 |
| C2 | 创建 `ConsulOptions.cs`（强类型配置类）| P0 | ✅ 已实现 |
| C3 | 创建 `ProgramConsulExtensions.cs`（封装 KV 加载 + 缓存回退 + Steeltoe）| P0 | ✅ 已实现 |
| C3.1 | 创建 `ConsulKvLoader.cs`（HTTP 拉取 `config/ruoyu/*` 共享配置）| P0 | ✅ 已实现 |
| C4 | 修改 `Program.cs` 调用 C3 | P0 | ✅ 已实现 |
| C5 | 在 `csproj` 引入 Steeltoe.Discovery.Consul 4.2.0 | P0 | ✅ 已实现（~~Steeltoe.Configuration.Consul~~ 包不存在） |
| C6 | 修改 `appsettings.json` 添加 `Consul:` 配置节（不再保留 `Mode` 开关）| P0 | ✅ 已实现 |
| C7 | 新增 `/consul/status` 和 `/consul/cache/invalidate` 端点 | P1 | 本轮补齐 |
| C8 | `/health` 端点增加 Consul 连通性检查 | P1 | 当前仍暂缓 |
| C9 | 修改 `start.sh` 固定以 Consul 模式注入共享配置入口，并把项目独有配置保留在脚本内 | P1 | 本轮收敛 |
| C10 | Consul 缓存目录默认使用容器内 `./data/consul`，宿主机挂载改为按需手动追加 | P0 | ✅ 已收敛 |
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
