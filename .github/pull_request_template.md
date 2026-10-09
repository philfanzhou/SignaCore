> 正文一律用中文填写。标题使用英文 conventional commit 格式（`feat:` / `fix:` / `docs:` …）。

## 概述

说明要解决的问题和本次改动。

Closes #

## 范围

引用所链接 issue 的“范围”，并逐项交代：

- **范围内，已完成：**

## 行为保证与兼容性

- **保证与不保证的内容：** 是否与 issue 一致；不适用写“无”。
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
