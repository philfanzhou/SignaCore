> 正文一律用中文填写。标题使用英文 conventional commit 格式（`feat:` / `fix:` / `docs:` …）。
> 一个 PR 只关闭一个可实施的 task issue。

## 概述

说明要解决的问题和本次改动。

Closes #

## 范围

引用所链接 issue 的“范围”，并逐项交代：

- **范围内，已完成：**
- **本次刻意不修：** 实施中发现的既有缺陷，每条都链接独立 issue；确认没有写“无”。

本 PR 不应改变 issue 明确排除的行为。如果确实改变，指出是哪一条验收标准要求的。

## 契约与兼容性

- **保证与非保证：** 是否与 issue 一致；不适用写“无”。
- **HTTP API、JSON、claims、JWT/JWKS 与认证：**
- **PostgreSQL/SQLite schema、migration 与数据：**
- **配置、管理端、容器与部署：**
- **英文使用者文档：**

没有影响的项目写“无”。

## 验证

列出实际执行的命令、结果和跳过原因：

- [ ] .NET Release 构建通过
- [ ] 单元测试通过
- [ ] 适用的 HTTP/认证/数据库集成测试通过
- [ ] 适用的 PostgreSQL 与 SQLite migration/contract 验证通过
- [ ] 管理端测试与生产构建通过
- [ ] 涉及容器或部署时，镜像和 smoke test 通过
- [ ] 行为、配置或用法变化时，英文文档已同步
- [ ] 不包含密钥、连接字符串、凭据、token 或私有数据

## Review 收敛

- [ ] 每个 commit 都能追溯到所链接 issue 的某条验收标准
- [ ] Review 意见已区分“本 PR 引入”与“既有问题”
- [ ] 既有问题均已转为独立 issue，没有在本 PR 顺手修复
- [ ] 若已进入第三轮 review，已完成范围审计并链接所有 follow-up issue
