# SignaCore 交互式管理员认证能力缺口

## 1. 文档目的

本文记录 SignaCore 当前在“为其他服务的管理控制台提供统一管理员认证”场景中的能力缺口，并给出建议的目标能力、安全边界和实施范围。

本文不是完整实现设计，也不意味着每个业务服务都必须依赖 SignaCore。它描述的是：当 SignaCore 被选为统一身份提供方时，还需要补充哪些标准能力，才能让浏览器管理控制台安全地使用重定向登录，而不接触管理员密码。

## 2. 背景

建议的服务管理模型是：

```text
SignaCore 或其他统一身份提供方
        │
        │ 认证：确认操作者是谁
        ▼
业务服务的管理控制台
        │
        │ 授权：判断该操作者能否管理本服务
        ▼
业务服务自己的管理角色与权限
```

在该模型中：

- 统一身份提供方负责认证、登录策略、凭据和会话；
- 每个业务服务负责本服务的管理授权；
- 普通业务服务不保存管理员密码；
- 业务服务使用稳定的 `issuer + subject` 标识管理员；
- 每个服务仍然拥有独立的 audience、权限边界和审计记录。

SignaCore 当前可以验证密码、短信、微信、LDAP 和 Refresh Token 凭据，并通过 Token Endpoint 签发访问令牌和 Refresh Token，但它还不能为浏览器提供标准的重定向式登录流程。

## 3. 当前能力

当前公开认证能力主要包括：

- OAuth Token Endpoint；
- Password Grant；
- Refresh Token Grant；
- SMS、LDAP、WeChat 扩展 Grant；
- RFC 7009 Refresh Token 撤销；
- JWT 签发；
- OpenID/OAuth 元数据发现；
- JWKS 发布；
- 应用注册、AppSecret 和每应用 audience；
- 应用级登录准入；
- 管理控制台自己的用户名、密码和 Cookie 会话。

当前明确不具备：

- Authorization Endpoint；
- Authorization Code Grant；
- PKCE；
- 面向第三方管理控制台的浏览器登录会话；
- 标准 OIDC `id_token`；
- UserInfo Endpoint；
- 标准 Redirect URI 注册和校验；
- 标准的浏览器单点登录和登出流程。

因此，SignaCore 当前更接近“直接凭据换取 Token 的认证服务”，还不是完整的浏览器交互式 OAuth/OIDC Provider。

## 4. 能力缺口

假设 `OrderService` 的管理页面希望使用 SignaCore 登录，目前通常只能选择以下方式之一：

1. `OrderService` 接收管理员用户名和密码，再调用 SignaCore Token Endpoint；
2. 管理 SPA 直接调用 SignaCore Token Endpoint；
3. `OrderService` 自己维护一套本地管理员账户；
4. 另外引入一个支持 OIDC 的身份提供方。

前三种方式都有明显问题：

- 业务服务或其前端重新接触管理员密码；
- 密码 Grant 不适合作为新的浏览器登录基础；
- 每个服务需要重复实现登录、锁定、MFA、找回和凭据安全；
- 无法获得标准的重定向登录和统一登录会话；
- 管理控制台与 SignaCore 的私有 Token 请求格式紧耦合；
- 很难安全支持第三方 SPA、BFF 和多个管理控制台。

核心缺口可以概括为：

> SignaCore 能签发 Token，但不能让浏览器应用通过 Authorization Code + PKCE，在不接触用户凭据的情况下取得代表当前操作者的 Token。

## 5. 目标能力

建议把目标定义为“支持 OIDC 的交互式授权能力”，而不只是增加一个形式上的 `/authorize` 路由。

最低目标包括：

1. Authorization Endpoint；
2. Authorization Code Grant；
3. 强制使用 PKCE，且只接受 `S256`；
4. Redirect URI 精确匹配；
5. 浏览器登录会话；
6. `state`、`nonce` 和 CSRF 防护；
7. 一次性、短时有效、不可明文恢复的授权码；
8. 面向不同应用的独立 audience；
9. `openid` Scope 和 `id_token`；
10. 更新后的标准发现元数据；
11. 登录、授权、失败和 Token 兑换审计；
12. 多实例下共享且一致的授权状态。

建议优先支持两类客户端：

### 5.1 BFF/服务端 Web 应用

- 客户端类型：Confidential Client；
- 使用 Authorization Code + PKCE；
- Token 保存在服务端；
- 浏览器只持有安全的 HttpOnly 会话 Cookie；
- 这是管理控制台的首选模式。

### 5.2 浏览器 SPA

- 客户端类型：Public Client；
- 使用 Authorization Code + PKCE；
- 不分配可长期保密的 AppSecret；
- 不允许 Password Grant；
- Access Token 应短时有效；
- 是否签发 Refresh Token 必须由独立策略控制。

对于高权限管理控制台，推荐 BFF，SPA 直持 Token 作为兼容模式而非默认模式。

## 6. 建议协议流程

```text
管理员浏览器        业务服务/BFF             SignaCore
     │                    │                       │
     │ 访问 /admin        │                       │
     ├───────────────────>│                       │
     │                    │ 生成 state、nonce、   │
     │                    │ code_verifier         │
     │ 302 Redirect       │                       │
     │<───────────────────┤                       │
     │ GET /oauth2/authorize                      │
     ├───────────────────────────────────────────>│
     │                    │                       │ 验证客户端、Redirect URI、PKCE
     │                    │                       │ 建立或复用登录会话
     │                    │                       │ 验证应用准入
     │ 302 Redirect + code + state                │
     │<───────────────────────────────────────────┤
     │ GET callback       │                       │
     ├───────────────────>│                       │
     │                    │ POST /oauth2/token    │
     │                    │ code + code_verifier  │
     │                    ├──────────────────────>│
     │                    │ Access/ID/Refresh     │
     │                    │<──────────────────────┤
     │ 管理会话 Cookie    │                       │
     │<───────────────────┤                       │
```

业务服务收到身份结果后，还必须执行自己的管理授权：

```text
issuer + subject
        │
        ▼
management_role_bindings
        │
        ▼
SystemAdministrator / Auditor / ConfigurationAdministrator
```

SignaCore 证明“这个人是谁”，业务服务判断“这个人能否管理我”。

## 7. 建议端点与发现元数据

建议新增或扩展：

```text
GET  /oauth2/authorize
POST /oauth2/token                 增加 authorization_code
GET  /oauth2/userinfo              若采用完整 OIDC
POST /oauth2/revoke                保留现有能力
GET  /.well-known/openid-configuration
GET  /.well-known/jwks
```

发现文档至少增加：

```json
{
  "authorization_endpoint": "https://identity.example.com/oauth2/authorize",
  "token_endpoint": "https://identity.example.com/oauth2/token",
  "userinfo_endpoint": "https://identity.example.com/oauth2/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["openid", "profile", "offline_access"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

现有直接凭据 Grant 可以为兼容性保留，但不应成为新管理控制台的推荐登录方式。

## 8. 应用注册模型需要扩展

当前应用的 Claims Callback 与 OAuth Redirect URI 是两个完全不同的概念：

- Claims Callback：SignaCore 在 Token 签发过程中调用业务系统，用来获取业务 Claims；
- Redirect URI：SignaCore 完成交互式授权后，把浏览器和授权码送回客户端。

不得复用现有 Callback 字段保存 Redirect URI。

建议为应用增加独立配置：

```text
client_type                  Confidential / Public
redirect_uris               精确注册的 URI 集合
post_logout_redirect_uris   可选
allowed_scopes
allow_authorization_code
allow_refresh_token
require_pkce                默认 true
require_consent             首方应用初期可为 false
```

安全约束：

- Redirect URI 必须完整字符串匹配，不使用通配符；
- HTTPS 为默认要求；
- 仅开发环境允许显式注册 Loopback HTTP；
- Public Client 不得依赖 AppSecret；
- Confidential Client 必须进行客户端认证；
- 每个管理控制台应注册为独立应用并使用独立 audience；
- 不签发可被所有管理服务共同接受的通用超级管理员 Token。

## 9. 授权码存储与多实例

授权码是安全敏感、一次性的共享状态，不能保存在实例本地内存或本地 SQLite 中，否则负载均衡后的 Token 请求可能落到另一实例并失败。

建议在共享业务数据库中保存：

```text
authorization_codes
├── id
├── code_digest
├── application_id
├── account_id
├── redirect_uri
├── scope
├── code_challenge
├── code_challenge_method
├── nonce_digest 或受保护 nonce
├── created_at
├── expires_at
├── consumed_at
└── session_id
```

要求：

- 只存授权码摘要，不保存可直接使用的明文授权码；
- 有效期建议 60 至 120 秒；
- Token 兑换时使用共享数据库事务原子消费；
- 同一授权码只能成功兑换一次；
- 客户端、Redirect URI 和 PKCE 验证必须与授权请求完全绑定；
- 重试和并发兑换不得签发两套 Token；
- 清理任务定期删除过期和已消费记录；
- PostgreSQL 和 SQLite 迁移历史都需要覆盖，但 SQLite 部署仍只支持单实例。

## 10. 浏览器登录会话

新的身份登录会话不应直接复用现有 SignaCore 管理后台 Cookie 的权限语义。

建议区分：

```text
SignaCore Authentication Session
    表示用户已经在身份提供方完成认证

SignaCore Administration Session
    表示该用户获准管理 SignaCore 自身
```

前者可用于完成其他应用的 Authorization Code 流程；后者仍需要 SignaCore 自己的管理员授权检查。

会话应满足：

- `HttpOnly`；
- `Secure`；
- 合适的 `SameSite` 策略；
- 登录和高风险操作的 CSRF 防护；
- 空闲和绝对过期时间；
- 密钥环在多实例间共享；
- 注销和管理员禁用后有明确的失效策略；
- 为未来 MFA、重新认证和认证强度 Claims 预留扩展点。

## 11. 管理员授权边界

新增交互式认证后，也不应让 SignaCore 统一拥有所有服务的业务管理权限。

推荐边界：

| 能力 | 所有者 |
| --- | --- |
| 用户凭据、登录、MFA | SignaCore |
| `issuer`、`subject`、认证时间和认证强度 | SignaCore |
| Token 签名和 audience | SignaCore |
| 是否允许登录某个应用 | SignaCore 的应用准入策略 |
| 是否为某服务管理员 | 该业务服务 |
| 管理员角色和具体操作权限 | 该业务服务 |
| 管理操作审计 | 该业务服务，必要时集中汇聚 |

业务服务可以保存如下绑定：

```text
management_role_bindings
├── issuer
├── subject
├── role
├── status
├── granted_by
├── granted_at
└── revoked_at
```

即使 Token 中包含角色 Claims，服务端也必须验证 issuer、签名、有效期和本服务 audience，不能因为 Claim 名为 `admin` 就跨服务授予管理权限。

## 12. 首个外部管理员的建立

普通业务服务接入 SignaCore 后，不需要创建本地管理员密码，但仍需解决首次授权问题。

建议流程：

1. 新服务第一次启动时生成一次性 Setup Code；
2. 操作员通过 SignaCore 完成交互式登录；
3. 操作员向新服务提交 Setup Code；
4. 新服务将当前 `issuer + subject` 绑定为第一个 `SystemAdministrator`；
5. 在一个事务中写入管理员绑定、默认配置、审计记录和安装完成状态；
6. Setup Code 立即失效；
7. 后续管理员只能由已授权管理员授予。

这里建立的是外部身份的本地授权关系，不是本地密码账户。

SignaCore 自身仍需保留本地 Bootstrap 管理员，因为身份服务在首次安装时不能依赖尚未建立的自身交互式登录能力。

## 13. 安全要求

实现至少应覆盖：

- Authorization Code 注入和重放；
- PKCE 降级；
- Redirect URI 开放重定向；
- Login CSRF；
- Authorization Response Mix-Up；
- `state` 和 `nonce` 验证；
- 客户端冒充；
- Token audience 混用；
- 管理 SPA 中的 Token 泄露；
- Refresh Token 轮换和重放；
- 多实例并发兑换；
- 账户禁用后的会话和 Token 行为；
- 日志中 Authorization Header、授权码、Token、密码和 Cookie 的脱敏；
- 登录、同意、拒绝、授权码兑换和失败事件的限流与审计。

高权限管理场景还建议：

- Access Token 使用较短有效期；
- 敏感操作要求近期认证；
- 为 MFA/认证强度预留 `acr`、`amr`；
- Break-glass 账号默认禁用、独立审计并定期轮换；
- 身份服务不可用时登录失败关闭，不自动降级到本地弱认证。

## 14. 非目标

第一阶段不建议同时实现：

- 动态客户端注册；
- 任意第三方应用自助接入；
- 复杂用户授权同意页面；
- Social Login 聚合平台；
- SAML；
- 完整 OAuth Device Flow；
- Token Exchange；
- 前通道和后通道注销的所有扩展规范；
- 集中管理所有业务服务的细粒度权限。

首期只服务受管理员控制、预先注册的第一方管理应用，可以显著缩小安全范围。

## 15. 建议实施阶段

### 阶段一：协议与数据模型

- 扩展应用注册模型；
- 增加 Redirect URI 和客户端类型；
- 增加授权码实体及两套 Provider 迁移；
- 定义 Scope、Claims、错误码和审计事件；
- 更新发现元数据契约测试。

### 阶段二：Authorization Code + PKCE

- 实现 Authorization Endpoint；
- 实现共享浏览器认证会话；
- Token Endpoint 支持 `authorization_code`；
- 强制 `S256`；
- 实现授权码原子消费和重放检测；
- 加入限流、CSRF 和 Redirect URI 安全测试。

### 阶段三：OIDC 身份层

- 支持 `openid` Scope；
- 签发并验证 `id_token`；
- 支持 `nonce`；
- 根据需要增加 UserInfo Endpoint；
- 完善 OIDC Discovery 元数据。

### 阶段四：管理服务接入

- 建立一个参考 BFF 管理控制台；
- 演示外部身份首次绑定；
- 演示服务本地角色授权；
- 验证多实例登录和回调；
- 验证 SignaCore 故障时已登录会话与新登录的行为。

### 阶段五：管理员增强

- 多管理员和分级角色；
- MFA 和重新认证；
- 会话查看与撤销；
- 更完善的注销；
- 风险事件和告警。

## 16. 验收标准

能力完成至少应满足：

1. 一个独立业务服务的 BFF 能通过 SignaCore 完成 Authorization Code + PKCE 登录；
2. 业务服务和浏览器都不接触管理员密码；
3. Redirect URI 未注册、大小写或路径不匹配时请求失败；
4. 不带 PKCE、使用 `plain`、Verifier 错误时 Token 兑换失败；
5. 授权码只能使用一次，并发兑换最多一次成功；
6. Authorization 请求与 Token 请求落到不同 SignaCore 实例时仍能成功；
7. Token 的 issuer、签名、有效期和业务服务 audience 均可验证；
8. 一个服务的管理 Token 不能用于另一个服务；
9. 业务服务可依据 `issuer + subject` 独立授予或撤销管理员角色；
10. 日志和审计中不出现密码、授权码、Token、Cookie、AppSecret 或 Authorization Header；
11. 发现文档只声明真实可用的端点和协议能力；
12. 现有 Password、SMS、LDAP、WeChat 和 Refresh Token 客户端保持兼容。

## 17. 需要进一步决策的问题

实现前仍需明确：

1. 首期只支持 BFF，还是同时支持纯 SPA；
2. 是否首期直接实现 OIDC，还是先交付 OAuth Authorization Code 后立即补齐 OIDC；
3. 是否签发管理用 Refresh Token，以及它的轮换和最长会话策略；
4. 是否需要用户授权同意页，还是只允许管理员预批准的第一方应用；
5. SignaCore 普通身份登录会话与自身管理后台会话如何隔离；
6. Password、SMS、LDAP、WeChat 中哪些认证方式允许建立浏览器会话；
7. MFA 和近期认证是否作为管理员场景上线前置条件；
8. 账户禁用和管理员撤权后，现有 Token、Refresh Token 和登录会话如何失效；
9. 是否提供标准 RP-Initiated Logout；
10. 对旧应用注册数据如何迁移，并确保现有 Claims Callback 不被误当作 Redirect URI。

## 18. 结论

SignaCore 当前的缺口不是简单少了一个管理登录页面，而是缺少一条标准、安全、适合浏览器的交互式认证协议链路。

建议目标是：

> 为受信任的第一方管理应用提供 OIDC Authorization Code + PKCE，使业务服务能够使用 SignaCore 认证管理员，同时继续由业务服务本地决定管理员角色和权限。

这项能力完成后，普通服务不再需要保存本地管理员密码；SignaCore 自身仍保留首次安装所需的 Bootstrap 管理员，并可逐步演进为多管理员、分级授权和 MFA 模型。
