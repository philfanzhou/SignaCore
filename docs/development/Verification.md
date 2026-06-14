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

## 4. gRPC 调用验证

使用 `grpcurl`：

```bash
# 列出服务
grpcurl -plaintext localhost:5001 list

# 调用 GetToken（密码登录）
grpcurl -plaintext -d '{"grant_type":"password","username":"admin","password":"$ADMIN_BOOTSTRAP_PASSWORD","app_id":"$TEACHER_PORTAL_APP_ID","app_secret":"$TEACHER_PORTAL_APP_SECRET"}' localhost:5001 QuantumZhou.Identity.AuthGrpcService/GetToken
```

预期返回 `TokenResponse`，包含 `access_token` 和 `refresh_token`。

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
