# RSA 密钥管理 — 设计说明 (DESIGN)

## 文件结构

```
backend/Domain/KeyManager.cs
backend/Host/Program.cs (JWKS 端点配置)
```

## 关键接口签名

```csharp
public interface IKeyManager {
    RsaSecurityKey GetCurrentKey();
    Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync();
    Task<bool> NeedsKeyRotationAsync();
    Task RotateKeyAsync();
    Task InitializationCompleted { get; }
}
```

## 依赖的数据库表

- [security_keys](../../database/tables/security_keys.md)

## 加密流程

### 主密钥派生

```
Master Key (来源: 环境变量 RSA_MASTER_KEY > 文件 > 自动生成)
    │
    ▼ HKDF(SHA256, masterKey, salt="QuantumZhou.Identity.KeyProtection",
           info="RSA-Private-Key-Encryption")
32-byte AES Key
```

### 私钥加密流程

```
Master Key
    │
    ▼ HKDF(SHA256, masterKey, randomSalt, info="RSA-Private-Key-Encrypt")
32-byte AES Key
    │
    ▼ AES-256-GCM(nonce, plaintext=pkcs8PrivateKey)
nonce(12 bytes) + tag(16 bytes) + ciphertext
    │
    ▼ Base64 编码
EncryptedPrivateKeyParams (存储到数据库)
```

**详细步骤：**

1. 生成随机 16-byte salt
2. 使用 HKDF(SHA256, masterKey, randomSalt, info="RSA-Private-Key-Encrypt") 派生 32-byte AES 密钥
3. 使用 AES-256-GCM 加密 PKCS#8 编码的私钥，生成 12-byte nonce 和 16-byte tag
4. 拼接 nonce(12) + tag(16) + ciphertext，进行 Base64 编码
5. 将 Base64 字符串和 randomSalt 一同存储为 `EncryptedPrivateKeyParams`

## 关键设计决策

| 决策 | 说明 |
|------|------|
| 启动阻塞 | 服务启动时阻塞等待 `KeyManager.InitializationCompleted`，在密钥初始化完成前不接受任何请求 |
| 主密钥丢失恢复 | 如果主密钥丢失导致私钥解密失败，旧密钥被标记为非活跃（deactivated），自动生成新的密钥对；所有基于旧密钥签发的 JWT 将失效 |
| JWKS 速率限制 | JWKS 端点配置独立的速率限制器（FixedWindow 策略，60 次/分钟），防止公钥查询被滥用 |
| JWKS 多密钥返回 | JWKS 端点返回所有未过期密钥（含已停用但未过期的），确保密钥轮换后旧 token 在过期前仍可验证。`IssuerSigningKeyResolver` 同样使用 `GetValidKeysAsync()`，JWT 库按 `kid` 自动匹配 |
| SQLite DateTimeOffset 兼容 | `SecurityKeyRepository.GetActiveKeyAsync` 和 `GetValidKeysAsync` 使用客户端求值处理 `ExpiresAt` 比较，因为 SQLite 的 EF Core 提供程序不支持 `DateTimeOffset` 的服务器端 LINQ 转译。security_keys 表数据量极小（通常 < 10 行），客户端过滤无性能影响 |
