# 部署与运维

## 构建与部署

- Dockerfile：`scripts/2.identity/1.build/Dockerfile`
- 部署脚本：`scripts/2.identity/2.deploy/start.sh`

## 配置项

### 数据库连接

```json
{
  "ConnectionStrings": {
    "Default": "Host=ruoyu-postgres;Port=5432;Database=quantumzhou_identity;Username=postgres;Password=postgres"
  }
}
```

### 服务端口

| 端口 | 协议 | 用途 |
|------|------|------|
| 5001 | gRPC | 内部服务间认证调用 |
| 5002 | HTTP | 对外 REST API（含 JWT 签发、健康检查、Metrics） |
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

### 管理员引导账户

```json
{
  "AdminBootstrap": {
    "Username": "admin",
    "Password": "Admin@2026"
  }
}
```

### Redis 配置

- 容器名: `ruoyu-redis`
- 密码: `redis123`
- 网络: `ruoyu-net`

### 日志配置

Identity 服务使用 JSON 格式日志：

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

## 健康检查

- 端点：`/health`（端口 5002）
- 包含数据库检查

## 监控

- Prometheus 指标端点：`http://<host>:5002/metrics`
- 已集成 OpenTelemetry（ASP.NET Core、Runtime、HttpClient）

## 数据库备份与恢复

```bash
# 备份
docker exec ruoyu-postgres pg_dump -U postgres quantumzhou_identity | gzip > backup_identity_$(date +%Y%m%d_%H%M%S).sql.gz

# 恢复
gunzip -c backup_identity_20240101_020000.sql.gz | docker exec -i ruoyu-postgres psql -U postgres -d quantumzhou_identity
```

## 常见问题排查

### 身份认证失败

1. 检查 Identity 服务状态：`curl http://localhost:5002/health`
2. 查看 Identity 服务日志：`docker logs ruoyu-identity | grep -i error`
3. 检查 KeyManager 初始化：`docker logs ruoyu-identity | grep "KeyManager initialization"`
4. 验证 JWKS 端点：`curl http://localhost:5002/.well-known/jwks`
5. 确认各服务中的 JWT Issuer 和 Audience 配置一致
