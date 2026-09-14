# SignaCore 协作规范

SignaCore 是 .NET 10 身份与认证服务，包含 Vue 3 管理控制台。它负责认证、RS256 JWT、refresh token、JWKS、管理 API、审计以及 PostgreSQL/SQLite 持久化。

## 维护方式

- 本文件是 AI 协作流程、review 政策和项目边界的统一入口。
- Codex 直接读取本文件；Claude Code 通过根目录 `CLAUDE.md` 导入本文件。
- `CONTRIBUTING.md` 是所有贡献者的工程入口。
- `docs/`、`CONTEXT.md`、ADR 与 `SECURITY.md` 是对应领域的事实来源；实现前先确认它们描述的是目标行为还是当前事实。

## 文档与沟通语言

- 流程与约束文档、GitHub issue/PR 正文和 review 全程使用中文；Issue 标题使用中文。
- PR 标题使用英文 conventional commit 格式（`feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `chore:` 等）。
- `README.md`、`docs/`、代码注释、自动化注释、API/异常消息和面向使用者的文字保持英文，这是本仓库既有公开契约。
- 代码标识符、配置键、JWT claim、HTTP 路由、命令和 commit message 保持原样/英文。

## 项目边界与架构

- Host 组合 `SignaCore.Domain`、`SignaCore.Database` 和 provider-specific migration projects；Domain 不得依赖 ASP.NET Core transport 类型。
- 下游系统通过 HTTP discovery、JWKS 和 API 集成，不直接引用本仓库程序集。
- 保持 `SignaCore` 根命名空间及项目/程序集名称一致；公共路由、JSON 字段、claims 和现有数据库表名默认稳定，破坏性变化必须有明确 migration 和兼容方案。
- 全局业务配置存于 `system_settings`，通过首次安装和认证后的管理页维护；除打开数据库所需的 provider/version/connection string 与外部 root key 外，不得把新业务配置塞进 `appsettings.json`。
- PostgreSQL migration 在 `src/SignaCore.Database`，SQLite migration 在 `src/SignaCore.Database.Migrations.Sqlite`；任何 schema 变更必须同时考虑两套 migration history。
- 可选 Consul discovery、OpenTelemetry、Prometheus、Serilog/Loki 与容器启动行为属于运维契约，修改时同步文档和 smoke test。

## 安全约束

- 绝不提交或记录 credential、application secret、OTP、refresh token、authorization header、private signing key、master key、连接字符串或个人数据。
- 不得暴露或回传管理员凭据、签名私钥、root key 或 token；日志和测试输出必须脱敏。
- 不得为特定消费方写入业务模型、品牌名、集成细节或 validator 配置；示例使用中性角色名（如 `OrderService`）。
- 使用 UTC 时间并传播 cancellation token；认证、授权、密钥轮换、refresh token、JWKS 和首次安装流程的行为变化必须补充安全/契约测试。

## 变更与验证

按改动风险运行最小充分验证：

```bash
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx --configuration Release --no-restore
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release --no-build --no-restore
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj --configuration Release --no-build --no-restore

npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin run test:coverage
npm --prefix src/SignaCore.Admin run build
```

涉及 PostgreSQL/SQLite schema、认证、HTTP contract、配置、镜像或启动脚本时，运行对应 migration、integration、container smoke test，并在无法本地运行时明确等待 CI 验证。

## 安全与变更纪律

- 增加依赖、改变公开 API、数据库、配置或部署方式前，先说明兼容性、迁移和回滚影响。
- 提交前检查英文文档链接、模板格式、secret、migration 对称性和仓库状态。
