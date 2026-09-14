# SignaCore 协作规范

SignaCore 是 .NET 10 身份与认证服务，包含 Vue 3 管理控制台。它负责认证、RS256 JWT、refresh token、JWKS、管理 API、审计以及 PostgreSQL/SQLite 持久化。

## 维护方式

- 本文件是 AI 协作流程、review 政策和项目边界的统一入口。
- Codex 直接读取本文件；Claude Code 通过根目录 `CLAUDE.md` 导入本文件。
- `CONTRIBUTING.md` 是所有贡献者的工程入口；若项目级交付或 review 政策变化，同时更新它和本文件。
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

## 范围纪律

一个 PR 只关闭一个可实施的 task issue。开始前完整阅读 issue 指向的实现、测试、公开文档、配置、迁移和部署路径；发现的既有缺陷是邻近债务，必须单独开 issue 并在目标 issue 的“已知邻近问题”中链接。

一个 issue 只有在以下条件都满足时才可标记 `status: ready`：

1. 写清 `## 范围`（含明确排除项）和可逐条验证的 `## 验收标准`。
2. 安全或健壮性任务写清保证、不保证和调用方责任；不适用时明确写“无”。
3. 将要改动的实现、测试、公开契约和 migration history 已经完整读过。
4. 邻近债务已经各自开成 issue 并完成链接；确认没有时明确写“无”。
5. 前置 issue 已关闭，GitHub 原生依赖关系与标签一致。
6. 复杂协议或状态任务已经提供权威语义模型，并用端到端场景证明状态、持久化关联、输入和敏感数据流闭合；不适用时明确写“不适用”及理由。

同时覆盖三个或以上公共 protocol surface、三个或以上有状态 artifact，或者把事务/并发、migration、敏感数据流和 capability activation 中的多个领域耦合在一起时，默认按 feature 级工作处理。若不能拆成一个可独立验证的切片，使用 `type: feature` / `size: XL` tracker 和有原生依赖关系的 task issues；tracker 不直接接收实现 PR。不能因为所有改动都能追溯到一组宽泛验收标准，就把 feature 级范围视为单一 task。

复杂协议或状态任务的权威语义模型至少覆盖：事件 × artifact × 结果、artifact × 持久化关联、endpoint × 外部输入、敏感值 × 信任边界/数据流，以及 implementation task × capability activation。解释性 prose 必须引用这些权威材料，不能在多份文档中复制第二套状态规则。链接、表格、语言和 build/test 检查只验证形式，不能替代逐场景语义演算。

实施中以 issue 范围为约束：不改变明确排除的行为，不顺手重构、改名、升级依赖或修复相邻缺陷；先找不变量，再在路径汇合处修复并覆盖相关输入集合。成功路径以及适用的失败、取消、安全、认证、密钥和并发行为必须与实现一起测试。若验收标准确实要求越过原范围，先更新或拆分 issue。

Review 意见先分类：本 PR 新增/实质修改的缺陷在本 PR 修复；既有或仅与 diff 相邻的问题单独开 issue 并链接，不能顺手修复。只有既有缺陷导致本 PR 某条验收标准无法验证时，才可作为越界例外，并明确指出该条标准。PR 进入第三轮 review 时暂停写代码，逐 commit 审计范围和语义闭合；不能追溯到验收标准的改动移出并改为 follow-up issue。若第三轮后仍反复出现跨文档、跨状态或跨数据流矛盾，停止逐 comment 增量修补，移除关联 issue 的 `status: ready`，将工作拆为 tracker/tasks 或先重建权威语义模型；“每个 commit 都可追溯”本身不构成继续维持原范围的理由。

## 变更与验证

按改动风险运行最小充分验证，并在 PR 中记录实际命令、结果和跳过原因：

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

纯文档的目标设计若定义未来协议、状态或安全行为，必须记录实际演算的端到端场景和结果。Markdown、链接、表格、语言、secret 扫描以及现有代码 CI 全绿，不得作为目标语义已经正确或闭合的证据。

## 安全与变更纪律

- 只读分析不得修改文件；保留用户已有且与任务无关的改动，不回退、覆盖、提交或推送它们。
- 增加依赖、改变公开 API、数据库、配置或部署方式前，先说明兼容性、迁移和回滚影响。
- 提交前检查英文文档链接、模板格式、secret、migration 对称性和仓库状态。

## 合并 PR 后

1. 使用 `gh pr view <编号> --json state,mergedAt,mergeCommit,baseRefName,headRefName` 确认远端 PR 已合并，目标分支包含结果；检查并按完成程度处理唯一关联 issue，无关联时明确说明。
2. 确认远端工作分支已删除；保留时说明原因。
3. 用 `git worktree list` 检查并安全清理不再需要的 worktree，然后运行 `git worktree prune`。
4. 用 `git switch main && git merge --ff-only origin/main` 更新目标分支；若被其他 worktree 占用，先处理占用者并说明。
5. 通过 PR 状态或实质 diff 确认改动已进入目标分支后，再清理本地工作分支和远端跟踪引用；不要把 `git branch -d` 失败当作未合并证据。
6. 汇报 PR、issue、远端/本地分支、worktree 和验证结果；未完成的清理必须说明原因与后续动作。

<!-- forge-steward:workflow begin lang=zh-CN -->
## ForgeSteward 工作流约束

本区块由 ForgeSteward 的 check-workflow 技能按标准模板维护，再次运行时会被整体替换为模板内容，请勿在区块内手工修改。项目需要不同约束时，写在区块之外；区块外的项目规则与本区块不一致时，以项目规则为准。

下文的 Change Request 指 Pull Request、Merge Request 等等待审查和合并的变更；Review Feedback 指 Change Request 上的 Comment、Discussion 或 Review Thread。

### 阶段与授权

- 工作分为准备、实施、审查合并和修复四个阶段。各阶段可以独立进行，不要求先运行其他阶段，也不自动串联下一阶段。
- 读取分析、修改 Issue、修改代码、推送、创建 Change Request 和合并分别需要授权。明确调用某阶段的技能即授权该技能的默认流程，例如审查合并阶段在满足合并条件时直接合并，不再逐项请求确认；用户本轮的明确限制优先。仅提及或自动加载技能，不构成外部写入或合并授权。
- 不绕过分支保护、必要审批或平台权限。

### 准备

- 准备阶段只做调查、实验、方案收敛和 Issue 整理，不提交生产实现，不创建实现 Change Request。
- Issue 同时满足以下条件才算 ready：
  - 原 Issue 或其可访问的证据中写明范围、排除项、实施方案、可逐条验证的验收、实现所属仓库和依赖；
  - 相关代码、测试和契约已按记录的基线完成审计；
  - 没有覆盖相同范围的开放 Change Request，且不依赖未合并的代码。
- 标签、清晰的描述或历史 CI 结果不能单独证明 ready；聊天记录不能代替写入原 Issue 的交接。
- 安全或健壮性相关的任务须写明保证与非保证的边界。
- 主线存在可以自主推进的阻塞时，先推进主线。真实的外部阻塞须记录已尝试的路径、缺少的输入、负责角色和解除条件；条件未变时不重复同一调查。

### 实施

- 按明确的 Issue 清单和顺序实施，不在实施中另行发现或追加任务。
- 每项基于当时最新的主线建立独立分支，不叠加其他未合并的变更；每项提交独立的 Change Request，并回链原 Issue。
- Issue 的排除项具有约束力，不顺手重构，不吸收独立问题。
- 逐条对应“验收条目 → 断言或可核对的证据 → 执行结果”；适用的失败、取消、安全和并发行为一并验证。CI 全绿不能代替逐条验收。
- 单项受阻时记录阻塞原因和解除条件，继续处理其余独立项，直到整批处理完毕。

### 审查与合并

- 合并须同时满足：原范围内的验收逐条成立；必要检查通过；没有未解决的范围内阻塞意见；审批、冲突状态和分支保护符合仓库政策；合并前的 head 与审查时一致。
- Review Feedback 分为四类：
  - 范围内必修项：对应具体的验收或保证，附证据和完成条件；
  - 独立既有缺陷：去重后另行登记，不阻塞本次变更，除非它直接破坏本次验收；
  - 可选建议：仓库未规定 Review 预算时，不要求在本次变更中实施，也不阻塞合并；
  - 平台门禁：单独报告，不当作代码缺陷。
- 范围争议须记录分歧、决策人和解除条件，不为满足意见而扩大实现。
- 合并后核对原 Issue 的验收再关闭；存在父子结构时，逐级核对直接父项的剩余范围。

### 修复

- 只修复范围内必修项、由当前分支确定性导致的 CI 失败，以及已确认的验收缺口。
- 在原 Change Request 的分支上提交并推送，然后交回复审。修复阶段不合并；已推送不等于已验收。

### 新发现

- 先检索开放和已关闭的记录，避免重复登记。
- 已关闭任务的验收遗漏回链原 Issue 和原 Change Request，记为返工；独立缺陷和可选改进分别登记，不自动扩大当前范围。
- 已接受的非保证边界在没有新证据时，不重复登记为缺陷。

### 交接与状态

- 保持工作可跨会话恢复：记录 Issue 与 Change Request 链接、实现仓库、基线与 head、验收证据、Review Feedback 的分类与轮次、已解决的意见、已接受的边界、阻塞和下一步。
- 更换会话或 Agent 时，不重置 Review 轮次，不重开已解决的意见。
- 区分 ready、已提交、已验收、已合并和已关闭；ready 或已提交都不能作为关闭原 Issue 的依据。
- 只清理本任务创建且没有未保存工作的临时环境；开放 Change Request 的分支予以保留。
<!-- forge-steward:workflow end -->

<!-- forge-steward:claude-rules begin lang=zh-CN -->
本仓库的其他项目规则位于 `CLAUDE.md`。不会自动加载该文件的 Agent，开始任务前须先读取并遵守其中的规则。
<!-- forge-steward:claude-rules end -->
