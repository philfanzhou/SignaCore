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

Client ← Contract（内部依赖，不暴露给调用方）
```

| 项目 | 依赖 |
|------|------|
| QuantumZhou.Identity.Contract | 无（纯 Proto 定义） |
| QuantumZhou.Identity.Database | Contract |
| QuantumZhou.Identity.Domain | Database |
| QuantumZhou.Identity.Service | Domain, Contract |
| QuantumZhou.Identity.Host | Service, Domain, Database, Contract |
| QuantumZhou.Identity.Client | Contract, JwtBearer |

## Client SDK

`QuantumZhou.Identity.Client` 是提供给业务服务接入 Identity 认证的 SDK 类库，封装了 gRPC 客户端注册、JWT Bearer 认证配置和认证端点（login/refresh/me/logout），使业务服务只需 3 行代码即可完成认证接入。

### 接入方式

```csharp
// Program.cs
builder.Services.AddIdentityClient(builder.Configuration);
// ...
app.UseIdentityClient();
app.MapIdentityAuthEndpoints();
```

```json
// appsettings.json
{
  "Identity": {
    "GrpcEndpoint": "http://localhost:5001",
    "AppId": "your_app_id",
    "AppSecret": ""
  },
  "Jwt": {
    "Issuer": "QuantumZhou.Identity",
    "Audience": "QuantumZhou.microservices",
    "JwksEndpoint": "http://localhost:5002/.well-known/jwks"
  }
}
```

### 提供的端点

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| POST | `/admin/auth/login` | AllowAnonymous | 用户名密码登录，代理 gRPC GetToken |
| POST | `/admin/auth/refresh` | AllowAnonymous | RefreshToken 刷新 |
| GET | `/admin/auth/me` | 需认证 | 获取当前用户信息（从 JWT Claims 读取） |
| POST | `/admin/auth/logout` | 需认证 | 登出（前端清除 Token） |

### 关键源文件

| 文件 | 用途 |
|------|------|
| [IdentityClientOptions.cs](../../backend/Client/IdentityClientOptions.cs) | 配置项定义 |
| [ServiceCollectionExtensions.cs](../../backend/Client/ServiceCollectionExtensions.cs) | AddIdentityClient() 扩展方法 + JwksFetcher |
| [ApplicationBuilderExtensions.cs](../../backend/Client/ApplicationBuilderExtensions.cs) | UseIdentityClient() + MapIdentityAuthEndpoints() |
| [AuthEndpoints.cs](../../backend/Client/AuthEndpoints.cs) | 认证端点实现 |

### JWKS 获取机制

JWT 验证需要从 Identity 服务获取 JWKS 公钥。SDK 使用 `JwksFetcher` 类（普通 HttpClient）手动获取并解析 JWKS，不依赖 `ConfigurationManager`（后者在 Docker 容器环境中存在静默失败问题）。密钥缓存 30 分钟，失败不缓存，下次请求重试。

## 详细设计

各功能点的详细设计见 [modules/](../modules/README.md) 目录。
