# 部署与运�?

## 构建与部�?

- Dockerfile：`backend/Host/Dockerfile`
- 部署脚本：`scripts/2.identity/2.deploy/start.sh`

## 配置�?

### 数据库连�?

```json
{
  "ConnectionStrings": {
    "Default": "Host=ruoyu-postgres;Port=5432;Database=quantumzhou_identity;Username=postgres;Password=postgres"
  }
}
```

### 服务端口

| 端口 | 协议 | 用�?|
|------|------|------|
| 5001 | gRPC | 内部服务间认证调�?|
| 5002 | HTTP | 对外 REST API（含 JWT 签发、健康检查、Metrics�?|
| 5010 | HTTP | 管理 API |

### JWT 配置

```json
{
  "Jwt": {
    "Issuer": "QuantumZhou.Identity",
    "Audience": "QuantumZhou.microservices",
    "TokenExpirationHours": 2
  },
  "RefreshToken": {
    "ExpirationDays": 7
  }
}
```

### 管理员引导账�?

管理员密码不再硬编码于配置文件，通过环境变量传入�?

```bash
# 必须设置的环境变�?
export ADMIN_BOOTSTRAP_USERNAME=admin
export ADMIN_BOOTSTRAP_PASSWORD=YourSecurePassword
```

appsettings.json �?`AdminBootstrap:Password` 默认为空，`PostConfigure` 从环境变量覆盖�?

### SMS 绕过验证码（仅限开�?预发布）

```bash
# 开发环境可设置绕过码，生产环境必须留空
export SMS_BYPASS_CODE=666666
```

�?`Sms:BypassCode` �?`SMS_BYPASS_CODE` 为空时，绕过逻辑完全禁用�?

### Teacher Portal 应用注册

```bash
# 必须设置的环境变�?
export TEACHER_PORTAL_APP_ID=your-app-id
export TEACHER_PORTAL_APP_SECRET=your-app-secret
```

�?AppId �?AppSecret 均未配置时，服务启动时跳过注册并输出警告日志�?

### Redis 配置

- 容器�? `ruoyu-redis`
- 密码: `redis123`
- 网络: `ruoyu-net`

### 日志配置

Identity 服务使用 JSON 格式日志�?

```json
{
  "Logging": {
    "Console": {
      "FormatterName": "json",
      "FormatterOptions": {
        "SingleLine": true,
        "IncludeScopes": true,
        "TimestampFormat": "yyyy-MM-ddTHH:mm:ss.fffZ"
      }
    }
  }
}
```

## 健康检�?

- 端点：`/health`（端�?5002�?
- 包含数据库检�?

## 监控

- Prometheus 指标端点：`http://<host>:5002/metrics`
- 已集�?OpenTelemetry（ASP.NET Core、Runtime、HttpClient�?

## 数据库备份与恢复

```bash
# 备份
docker exec ruoyu-postgres pg_dump -U postgres quantumzhou_identity | gzip > backup_identity_$(date +%Y%m%d_%H%M%S).sql.gz

# 恢复
gunzip -c backup_identity_20240101_020000.sql.gz | docker exec -i ruoyu-postgres psql -U postgres -d quantumzhou_identity
```

## 常见问题排查

### 身份认证失败

1. 检�?Identity 服务状态：`curl http://localhost:5002/health`
2. 查看 Identity 服务日志：`docker logs ruoyu-identity | grep -i error`
3. 检�?KeyManager 初始化：`docker logs ruoyu-identity | grep "KeyManager initialization"`
4. 验证 JWKS 端点：`curl http://localhost:5002/.well-known/jwks`（应返回所有未过期密钥�?
5. 确认各服务中�?JWT Issuer �?Audience 配置一�?

### 密钥轮换后旧 token 失效

JWKS 端点返回所有未过期密钥（含已停用但未过期的），确保密钥轮换后旧 token 在过期前仍可验证。如果旧 token 仍然失效�?

1. 检查旧密钥�?`ExpiresAt` 是否已过期：`docker logs ruoyu-identity | grep "GetValidKeysAsync"`
2. 确认调用方缓存了 JWKS 响应且会定期刷新（建议缓存时�?�?1 小时�?
