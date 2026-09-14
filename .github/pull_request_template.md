> 正文一律用中文填写。标题使用英文 conventional commit 格式（`feat:` / `fix:` / `docs:` …）。

## 概述

说明要解决的问题和本次改动。

Closes #

## 范围

引用所链接 issue 的“范围”，并逐项交代：

- **范围内，已完成：**
- **本次刻意不修：** 实施中发现的既有缺陷，每条都链接独立 issue；确认没有写“无”。

## 契约与兼容性

- **保证与非保证：** 是否与 issue 一致；不适用写“无”。
- **HTTP API、JSON、claims、JWT/JWKS 与认证：**
- **PostgreSQL/SQLite schema、migration 与数据：**
- **配置、管理端、容器与部署：**
- **英文使用者文档：**

没有影响的项目写“无”。

## 语义闭合

复杂协议、状态、持久化或安全设计填写；不适用写明理由：

- **权威语义模型：** 链接 event/artifact、persistence、external input、sensitive data-flow 与 capability activation 材料。
- **端到端场景：** 列出本 PR 实际演算或自动化验证的场景和唯一结果。
- **重复规则检查：** 说明解释性 prose 如何引用权威模型，而不是复制第二套状态规则。

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
