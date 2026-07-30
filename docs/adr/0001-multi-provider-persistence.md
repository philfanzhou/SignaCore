---
status: accepted
date: 2026-07-30
---

# 使用 EF Core Provider Adapter 支持多数据库持久化

QuantumZhou.Identity 当前使用 EF Core 8 和 PostgreSQL，但数据库注册、类型映射、初始化、Migration 与部署配置均直接依赖 PostgreSQL。为允许同一服务在不同部署规模下选择合适的关系数据库，同时控制 ORM 维护成本和性能风险，决定继续以 EF Core 8 作为唯一 ORM，通过 provider adapter 支持 PostgreSQL、MySQL、MariaDB 和 SQLite；不引入第二套 ORM 或数据访问栈。

## 决定

### Provider 与部署边界

- PostgreSQL 15+ 是默认选择，并必须保持现有数据库、数据和行为兼容。
- 新部署支持 MySQL 8.0/8.4、MariaDB 10.11/11.4，以及 EF Core SQLite provider 随程序提供的 SQLite 版本。
- SQLite 仅支持单实例且数据库文件必须位于实例本地磁盘；多实例、共享存储或高写并发部署必须使用 PostgreSQL、MySQL 或 MariaDB。
- 服务以单一镜像交付，通过启动配置选择 provider；每个进程只注册和初始化被选择的 provider。
- Provider 在实例启动时确定，不支持运行时切换，也不提供 PostgreSQL 与其他数据库之间的数据搬迁能力。

### 配置契约

数据库配置统一使用一个 `Database` 节：

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=...;Port=5432;Database=quantumzhou_identity;Username=...;Password=..."
  }
}
```

- `Database:Provider` 只允许 `PostgreSQL`、`MySQL`、`MariaDB`、`SQLite`。
- PostgreSQL、MySQL 和 MariaDB 必须显式配置 `Database:ServerVersion`；SQLite 禁止配置该项。
- `Database:ConnectionString` 是唯一连接字符串入口。
- 不保留 `PostgreSql:*`、`ConnectionStrings:Default`、`ConnectionStrings:PostgreSQL` 或 `Database:Name` 的运行时兼容分支。
- 缺少新配置、发现旧键、provider 与连接串不匹配或数据库版本不受支持时，服务启动失败；不得静默猜测或降级。
- 日志不得输出密码或完整连接字符串。

### Schema 生命周期

- 现有 PostgreSQL Migration 文件和数据库中的 `__EFMigrationsHistory` 原样保留，不重置、不重放。
- PostgreSQL、SQLite 和 MySQL-compatible 分别维护 Migration 链；MySQL 与 MariaDB 共用迁移源码，但必须分别验证。
- 服务保留启动时自动建库和迁移。多实例通过 provider 级数据库锁串行化迁移：PostgreSQL 使用 advisory lock，MySQL/MariaDB 使用 `GET_LOCK`，SQLite 遵循单实例约束。
- 实例在迁移成功前不得进入 Ready 状态；迁移失败必须阻止启动。
- 迁移必须遵循 expand-contract，保证滚动部署期间相邻版本可以共存。
- 现有 PostgreSQL 升级前先校验 schema。大小写规范化预检发现碰撞时必须 fail-closed，不得自动合并、删除或重命名数据。

### 可移植数据语义

- 领域实体继续使用 `DateTimeOffset`。持久化时间统一表示 UTC 瞬间并精确到微秒，读取后偏移统一为 `+00:00`。
- PostgreSQL 继续使用 `timestamptz`，MySQL/MariaDB 使用 `datetime(6)`，SQLite 使用可排序的 64 位 Unix 微秒值。
- 需要大小写不敏感的值使用 `Normalize(FormC)` 后再 `ToUpperInvariant()` 生成规范化值；原始值保留用于展示。
- 登录用户名、登录失败锁定用户名、AppId、ProviderName，以及面向人的用户名、昵称和备注搜索使用大小写不敏感语义。
- Refresh Token、AppSecret、外部 `ProviderUserId`、JWT `kid`、CorrelationId、审计快照及其他自由文本保持大小写敏感。
- 唯一约束和查询使用规范化值实现，不依赖数据库默认 collation。

### 一致性与验证

- Refresh Token 必须原子消费，同一 Token 的并发换票最多成功一次。
- OTP 成功验证与删除必须原子完成；OTP 和密码失败次数的并发递增不得丢失。
- 四个 provider 必须运行同一套真实数据库契约测试，覆盖建库、Migration、CRUD、唯一约束、大小写语义、UTC 时间、分页、清理和认证并发。
- CI 合并门禁使用 PostgreSQL 15、MySQL 8.4、MariaDB 11.4 和临时文件 SQLite；EF InMemory 测试不能替代 provider 契约测试。
- PostgreSQL 改造前后必须在相同环境和数据下进行性能回归验证：关键路径 p95 延迟回退不超过 10%，吞吐下降不超过 5%，SQL 往返次数不得增加，稳态内存和不含 Migration 的正常启动耗时增长不超过 10%。

## 考虑过的方案

- **Dapper 或 Linq2DB**：运行时更轻，但需要重写依赖 change tracking 和统一 `SaveChangesAsync` 的仓储与事务语义，并另行解决 schema 迁移，整体维护成本更高。
- **FreeSql 或 SqlSugar**：具备多数据库和 Code First 能力，但替换现有 EF Core 持久化层的收益不足以抵消迁移风险，并会引入新的框架知识和行为差异。
- **多套 provider 专用镜像**：发布体积更小，但会产生多套镜像、版本和流水线；选择单一镜像以降低运维分叉。
- **生产环境独立迁移任务**：并发和权限边界更清晰，但不满足已确认的启动时自动初始化要求，因此改用 provider 数据库锁和 expand-contract 约束。

## 后果

- 业务层和仓储抽象继续使用 EF Core 语义，但基础设施必须隔离 provider 注册、类型映射、建库、Migration 锁和 schema 校验。
- 新增 provider 会扩大发布包和 CI 矩阵；未被选择的 provider 不得建立连接或启动后台工作。
- 大小写不敏感与并发原子性是对现有实现行为的有意收敛，必须同步规格和回归测试。
- 新增数据库能力不表示所有数据库适用于所有部署拓扑；SQLite 的单实例边界是正式支持契约。
