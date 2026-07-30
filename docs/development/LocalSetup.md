# 本地环境搭建 (LocalSetup)

## 前置依赖

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| .NET SDK | 8.0+ | `dotnet --version` 验证 |
| 关系数据库 | PostgreSQL 15+、MySQL 8.0/8.4、MariaDB 10.11/11.4 或 SQLite | PostgreSQL 是默认选择；SQLite 可用于无服务器的单实例本地开发 |
| Node.js | 18+（可选） | 仅管理前端开发时需要 |

## 快速启动

### 1. 克隆并还原

```bash
cd QuantumZhou.Identity
dotnet restore
```

### 2. 数据库配置

数据库统一使用 `Database` 配置节。PostgreSQL 示例：

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres;Password=postgres"
  }
}
```

不希望安装数据库服务器时，可以改用本地文件 SQLite：

```json
{
  "Database": {
    "Provider": "SQLite",
    "ConnectionString": "Data Source=./data/identity.db"
  }
}
```

SQLite 只支持单服务实例和实例本地磁盘。旧数据库配置键没有兼容分支。

### 3. 启动服务

```bash
cd backend/Host
dotnet run
```

默认端口：
- HTTP: 5002（业务/认证）

HTTP 端口可通过 `appsettings.json` 的 `Endpoints:Http` 修改。

### 4. 首次启动自动初始化

服务启动时自动执行以下操作：

1. **数据库建库与迁移**：根据 Provider 选择独立迁移链并持有数据库迁移锁
2. **PostgreSQL 兼容处理**：保留既有 schema reconciliation 与迁移历史 stamping
3. **规范化升级**：现有 PostgreSQL 数据先检测大小写碰撞，再回填规范化列并收紧约束
4. **Admin Bootstrap**：根据 `AdminBootstrap:Username` 和 `AdminBootstrap:Password` 创建初始管理员账户
5. **Bootstrap Apps 预置**（可选）：读取 `data/bootstrap-apps.json` 文件（若存在），预置应用注册信息
6. **RSA 密钥初始化**：`KeyManager` 生成或加载活跃密钥对

> **数据目录管理**：`data/` 目录（含 `master-key/` 子目录、`bootstrap-apps.json`）由程序自动创建和管理。`KeyManager` 在首次启动时自动创建 `master-key/` 子目录并生成主密钥文件；部署脚本如需预置应用，在启动容器前将 `bootstrap-apps.json` 写入 `data/` 目录。开发者无需手动创建任何业务子目录。

## 运行测试

```bash
# 单元测试
dotnet test backend/Tests/unit/QuantumZhou.Identity.Tests.csproj

# 集成测试（需要运行中的服务）
dotnet test backend/Tests/integration/QuantumZhou.Identity.IntegrationTests.csproj

# 四数据库契约矩阵（需要 Docker）
RUN_IDENTITY_DATABASE_CONTRACTS=true \
dotnet test backend/Tests/integration/QuantumZhou.Identity.IntegrationTests.csproj \
  --filter 'FullyQualifiedName~DatabaseContractTests'
```
