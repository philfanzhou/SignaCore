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
cd services/QuantumZhou.Identity
dotnet restore
```

### 2. 数据库配置

**SQLite（默认，零配置）**：无需额外操作，首次启动自动创建 `quantumzhou_identity.db`。

**PostgreSQL**：修改 `backend/Host/appsettings.json`：

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "AutoMigrate": true
  },
  "ConnectionStrings": {
    "PostgreSQL": "Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres"
  }
}
```

PostgreSQL 密码可通过环境变量 `DB_PASSWORD` 注入，无需写入配置文件。

### 3. 启动服务

```bash
cd backend/Host
dotnet run
```

默认端口：
- gRPC: 5001
- HTTP: 5002

可通过 `appsettings.json` 的 `Endpoints:Grpc` 和 `Endpoints:Http` 修改。

### 4. 首次启动自动初始化

服务启动时自动执行以下操作（`Database:AutoMigrate = true` 时）：

1. **数据库迁移**：SQLite 使用 `EnsureCreated()`，PostgreSQL 使用 `Database.Migrate()`
2. **Schema Reconciliation**（仅 PostgreSQL）：检查并补齐缺失的列（如 `accounts.nickname`）
3. **Migration Stamping**（仅 PostgreSQL）：如果数据库有表但无迁移历史，自动标记初始迁移
4. **Admin Bootstrap**：根据 `AdminBootstrap:Username` 和 `AdminBootstrap:Password` 创建初始管理员账户
5. **Teacher Portal 测试应用**：自动创建 AppId=`a6eab9bd87404c0ababc910114d11a62` 的测试应用
6. **RSA 密钥初始化**：`KeyManager` 生成或加载活跃密钥对

### 5. 禁用自动迁移

生产环境设置 `Database:AutoMigrate = false`，手动执行：

```bash
cd backend/Database
dotnet ef database update --project ../Host
```

## 运行测试

```bash
# 单元测试
dotnet test test/QuantumZhou.Identity.Tests.csproj

# 集成测试（需要运行中的服务）
dotnet test QuantumZhou.Identity.IntegrationTests/
```
