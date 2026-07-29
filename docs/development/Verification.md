# 验证方法 (Verification)

> 服务启动后的验证步骤。适用于本地开发和部署验证。

## 1. 健康检查

```bash
curl http://localhost:5002/health
```

预期：返回 200 OK。

## 2. OIDC Discovery

```bash
curl http://localhost:5002/.well-known/openid-configuration
```

预期返回 JSON，包含 `issuer`、`jwks_uri`、`token_endpoint` 等字段。

## 3. JWKS 端点

```bash
curl http://localhost:5002/.well-known/jwks
```

预期返回 JSON，`keys` 数组包含一个或多个 RSA 公钥（`kty: "RSA"`, `alg: "RS256"`）。

注意：JWKS 端点有速率限制（60 次/分钟），超出返回 429。

## 4. HTTP 认证 API 验证

使用 `curl` 调用 `/api/auth/*` 端点：

> 调用 `/api/auth/*` 端点需使用有效的 AppId/AppSecret（从 `data/bootstrap-apps.json` 预置的应用或通过 Admin API 注册的应用获取）。

```bash
# 调用 POST /api/auth/token（密码登录）
curl -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -H "X-Admin-AppId: <your-app-id>" \
  -H "X-Admin-AppSecret: <your-app-secret>" \
  -d '{"grantType":"password","username":"admin","password":"<your-admin-password>"}'

# 调用 POST /api/auth/token（刷新令牌）
curl -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -H "X-Admin-AppId: <your-app-id>" \
  -H "X-Admin-AppSecret: <your-app-secret>" \
  -d '{"grantType":"refresh_token","refreshToken":"<your_refresh_token>"}'

# 调用 POST /api/auth/sms-code（请求短信验证码）
curl -X POST http://localhost:5002/api/auth/sms-code \
  -H "Content-Type: application/json" \
  -H "X-Admin-AppId: <your-app-id>" \
  -H "X-Admin-AppSecret: <your-app-secret>" \
  -d '{"phone":"13800138000"}'

# 调用 POST /api/auth/revoke（吊销刷新令牌）
curl -X POST http://localhost:5002/api/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<your_refresh_token>"}'
```

预期返回 JSON `TokenResponse`，包含 `accessToken` 和 `refreshToken` 字段。

## 5. JWT 验证

获取 access_token 后，解码验证：

```bash
# 解码 JWT header（查看 kid 和 alg）
echo "<access_token>" | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# 解码 JWT payload（查看 sub、name、auth_method 等）
echo "<access_token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

验证要点：
- `iss` = `QuantumZhou.Identity`
- `aud` = `QuantumZhou.microservices`
- `exp` 在当前时间之后
- `kid` 与 JWKS 端点返回的 `kid` 一致

## 5.1 Bootstrap Admin 刷新角色保持验证

此流程验证 bootstrap admin 使用 Refresh Token 换票后仍保留 `role=admin`，并验证普通账户无法通过 refresh 请求伪造 `username=admin` 提权。

> 真实 Token、密码和 Cookie 不得写入文档、日志或提交记录。

```bash
# 1. bootstrap admin 密码登录
curl -s -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"grantType":"password","username":"admin","password":"<ADMIN_BOOTSTRAP_PASSWORD>"}'
# 解码第一个 access_token 的 payload，确认 role 数组包含 "admin"

# 2. 使用返回的 refreshToken 执行 refresh_token grant
curl -s -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"grantType":"refresh_token","refreshToken":"<refresh_token_from_step_1>"}'
# 解码第二个 access_token 的 payload，确认 role 数组仍包含 "admin"

# 3. 普通账户伪造提权验证（普通账户的 refreshToken + 恶意 username=admin）
curl -s -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"grantType":"refresh_token","refreshToken":"<regular_user_refresh_token>","username":"admin"}'
# 解码 access_token 的 payload，确认 role 数组不包含 "admin"
```

预期：
- 第一个 Access Token 包含 `role=admin`；
- 第二个 Access Token（refresh 后）仍包含 `role=admin`；
- 普通账户即使附带 `username=admin`，其 refresh 后的 Access Token 也不包含 `role=admin`。

> 此验证不要求 DocLibrary 配置或发送 AppId/AppSecret。DocLibrary refresh 请求只发送 `grantType` 和 `refreshToken`，由 Identity 在服务端基于已验证账户 ID 重新识别 bootstrap admin。

## 6. Admin API 验证

```bash
# 管理员登录
curl -X POST http://localhost:5002/api/admin/session/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"$ADMIN_BOOTSTRAP_PASSWORD"}' \
  -c cookies.txt

# 获取当前会话
curl http://localhost:5002/api/admin/session/me -b cookies.txt

# 查询用户列表
curl http://localhost:5002/api/admin/users -b cookies.txt
```

## 7. Prometheus 指标

```bash
curl http://localhost:5002/metrics
```

预期返回 Prometheus 格式的指标。业务指标由 `AuthMetrics`（backend/Domain/AuthMetrics.cs）定义，Prometheus 导出后点号转为下划线：

| 指标名 | 类型 | 标签 | 说明 |
|--------|------|------|------|
| `auth_login_success_total` | counter | `grant_type` | 登录成功次数 |
| `auth_login_failure_total` | counter | `grant_type`、`reason` | 登录失败次数 |
| `auth_login_duration` | histogram | `grant_type` | 登录请求耗时（ms） |
| `auth_account_creation_total` | counter | `source` | 账户创建次数 |

## 8. Swagger UI（仅开发环境）

访问 `http://localhost:5002/swagger`，可浏览 Admin/Gateway/Profile API 文档。

## 9. Loki smoke test 验证

启动日志中应包含 `Loki connectivity check succeeded` 和 `Loki push smoke test succeeded` 两条 INFO 日志。如果只有前者没有后者（或后者失败），按 `Configuration.md` "Loki 地址注入" 一节的容错机制说明与下方手工验证三阶段排查。

手工验证三阶段：

```bash
LOKI_URI="http://<host>:3100"

# 1. 进程级
curl -s "$LOKI_URI/ready"
# 预期：ready

# 2. 写入（distributor + ingester 端到端）
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"streams":[{"stream":{"service":"QuantumZhou.Identity.smoketest"},"values":[["'$(date +%s%N)'","manual test"]]}]}' \
  "$LOKI_URI/loki/api/v1/push"
# 预期：204 No Content

# 3. 查询（querier + ingester ring）
curl -s "$LOKI_URI/loki/api/v1/labels"
# 预期：200 OK，body 为 JSON 数组
```

如果步骤 2 返回 500 含 `replicas required` 字样，或步骤 3 持续超时，说明 Loki 端 `replication_factor` 没设对，回到 `script/env-script/04-loki/Configuration.md` 排查。
