# 本地环境搭建 (LocalSetup)

## 前置依赖

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| .NET SDK | 8.0+ | `dotnet --version` 验证 |
| PostgreSQL | 12+（可选） | 生产数据库；不安装时默认使用 SQLite |
| Node.js | 18+（可选） | 仅管理前端开发时需要 |

## 快速启动

### 1. 克隆并还原

```bash
cd src/services/QuantumZhou.Identity
dotnet restore
```

### 2. 数据库配置

**SQLite（默认，零配置）**：无需额外操作，首次启动自动创建 `quantumzhou_identity.db`。

**PostgreSQL**：正式容器启动路径要求由 Consul 提供数据库配置；如仅做本地手工诊断，可临时修改 `backend/Host/appsettings.json`：

```json
{
  "Database": {
    "Provider": "PostgreSQL"
  },
  "ConnectionStrings": {
    "PostgreSQL": "Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres"
  }
}
```

项目级 `start.sh` 不再注入 `DB_PASSWORD`；正式部署时请在 Consul KV 中提供 `PostgreSql:Password`。

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

1. **数据库迁移**：SQLite 使用 `EnsureCreated()`，PostgreSQL 使用 `Database.Migrate()`
2. **Schema Reconciliation**（仅 PostgreSQL）：检查并补齐缺失的列（如 `accounts.nickname`）
3. **Migration Stamping**（仅 PostgreSQL）：如果数据库有表但无迁移历史，自动标记初始迁移
4. **Admin Bootstrap**：根据 `AdminBootstrap:Username` 和 `AdminBootstrap:Password` 创建初始管理员账户
5. **Bootstrap Apps 预置**（可选）：读取 `data/bootstrap-apps.json` 文件（若存在），预置应用注册信息
6. **RSA 密钥初始化**：`KeyManager` 生成或加载活跃密钥对

> **数据目录管理**：`data/` 目录（含 `master-key/` 子目录、`bootstrap-apps.json`）由程序自动创建和管理。`KeyManager` 在首次启动时自动创建 `master-key/` 子目录并生成主密钥文件；部署脚本如需预置应用，在启动容器前将 `bootstrap-apps.json` 写入 `data/` 目录。开发者无需手动创建任何业务子目录。

## 运行测试

```bash
# 单元测试
dotnet test test/unit/QuantumZhou.Identity.Tests.csproj

# 集成测试（需要运行中的服务）
dotnet test test/integration/QuantumZhou.Identity.IntegrationTests.csproj
```
