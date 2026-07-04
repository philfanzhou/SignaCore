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

```bash
# 调用 POST /api/auth/token（密码登录）
curl -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -H "X-Admin-AppId: $TEACHER_PORTAL_APP_ID" \
  -H "X-Admin-AppSecret: $TEACHER_PORTAL_APP_SECRET" \
  -d '{"grantType":"password","username":"admin","password":"$ADMIN_BOOTSTRAP_PASSWORD"}'

# 调用 POST /api/auth/token（刷新令牌）
curl -X POST http://localhost:5002/api/auth/token \
  -H "Content-Type: application/json" \
  -H "X-Admin-AppId: $TEACHER_PORTAL_APP_ID" \
  -H "X-Admin-AppSecret: $TEACHER_PORTAL_APP_SECRET" \
  -d '{"grantType":"refresh_token","refreshToken":"<your_refresh_token>"}'

# 调用 POST /api/auth/sms-code（请求短信验证码）
curl -X POST http://localhost:5002/api/auth/sms-code \
  -H "Content-Type: application/json" \
  -H "X-Admin-AppId: $TEACHER_PORTAL_APP_ID" \
  -H "X-Admin-AppSecret: $TEACHER_PORTAL_APP_SECRET" \
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

预期返回 Prometheus 格式的指标，包含 `auth_login_total`、`auth_login_duration` 等。

## 8. Swagger UI（仅开发环境）

访问 `http://localhost:5002/swagger`，可浏览 Admin/Gateway/Profile API 文档。

## 9. Loki smoke test 验证

启动日志中应包含 `Loki connectivity check succeeded` 和 `Loki push smoke test succeeded` 两条 INFO 日志。如果只有前者没有后者（或后者失败），按 `Configuration.md` "探活失败排查清单" 排查。

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
