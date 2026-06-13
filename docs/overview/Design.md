# 服务级架构 (Design)

## 分层说明

```
┌─────────────────────────────────────────────────────┐
│                      Host                            │
│  Controllers (Admin/Gateway/Profile) + SPA Hosting   │
├─────────────────────────────────────────────────────┤
│                     Service                          │
│  AuthServiceImpl + gRPC Interceptors                 │
├─────────────────────────────────────────────────────┤
│                     Domain                           │
│  Validators + TokenService + KeyManager + Callback   │
├─────────────────────────────────────────────────────┤
│                    Database                          │
│  DbContext + Repositories + Entities + Migrations    │
├─────────────────────────────────────────────────────┤
│                    Contract                          │
│  Proto Definitions (auth.proto)                      │
└─────────────────────────────────────────────────────┘
```

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| .NET | 8.0 | 运行时 |
| ASP.NET Core | 8.0 | Web 框架 |
| gRPC | 内置 | 服务间通信 |
| EF Core | 8.0 | ORM |
| PostgreSQL | 12+ | 生产数据库 |
| SQLite | 内置 | 开发数据库 |
| BCrypt.Net | - | 密码哈希 |
| OpenTelemetry | - | 可观测性 |
| JWT | System.IdentityModel | 令牌签发 |
| Vue 3 + Vite | - | 管理前端 |

## 项目依赖关系

```
Contract ← Database ← Domain ← Service ← Host
                                    ↑         │
                                    └─────────┘
```

| 项目 | 依赖 |
|------|------|
| QuantumZhou.Identity.Contract | 无（纯 Proto 定义） |
| QuantumZhou.Identity.Database | Contract |
| QuantumZhou.Identity.Domain | Database |
| QuantumZhou.Identity.Service | Domain, Contract |
| QuantumZhou.Identity.Host | Service, Domain, Database, Contract |

## 详细设计

各功能点的详细设计见 [modules/](../modules/README.md) 目录。
