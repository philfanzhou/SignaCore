# RSA 密钥管理 — 设计说明 (DESIGN)

## 文件结构

```
backend/Domain/Keys/KeyManager.cs               # 密钥生命周期编排（加载/轮换/对外提供）
backend/Domain/Keys/IMasterKeyProvider.cs       # 主密钥来源抽象
backend/Domain/Keys/FileMasterKeyProvider.cs    # 环境变量 → 文件 → 生成
backend/Domain/Keys/IPrivateKeyProtector.cs     # 私钥静态加密抽象
backend/Domain/Keys/AesGcmPrivateKeyProtector.cs # AES-GCM + HKDF 实现
backend/Host/Program.cs (JWKS 端点配置)
```

三者职责分离：`KeyManager` 不接触任何密钥字节，主密钥从哪来、私钥怎么加解密
分别由 `IMasterKeyProvider` 与 `IPrivateKeyProtector` 决定。

## 关键接口签名

```csharp
public interface IKeyManager {
    RsaSecurityKey GetCurrentKey();
    Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync();
    Task<bool> NeedsKeyRotationAsync();
    Task RotateKeyAsync();
    Task InitializationCompleted { get; }
}

public interface IMasterKeyProvider {
    byte[] GetMasterKey();
}

public interface IPrivateKeyProtector {
    (string EncryptedKey, string Salt) Protect(byte[] pkcs8PrivateKey);
    byte[] Unprotect(string encryptedKey, string salt);
}
```

> 加密字节格式（`nonce(12) || tag(16) || ciphertext`，salt 分列存储）是**持久化契约**，
> 由 `AesGcmPrivateKeyProtectorTests` 用独立重写的参考实现双向交叉验证。

## 依赖的数据库表

- [security_keys](../../../database/tables/security_keys.md)

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

## 主密钥文件路径

- 容器内路径：`data/master-key/master-key.json`（`AppContext.BaseDirectory` + `data/master-key`，容器内 ContentRoot 为 `/app`）
- `start.sh` 将宿主机 `data/` 目录挂载到容器 `/app/data`，主密钥文件位于该挂载点下
- 程序检测 `data/master-key/` 子目录是否存在，**不存在时自动创建**（`Directory.CreateDirectory`），再写入 `master-key.json`；启动脚本不预先创建任何业务子目录

## 关键设计决策

| 决策 | 说明 |
|------|------|
| 主密钥文件路径 | `data/master-key/master-key.json`，随 `data/` 目录挂载到容器 `/app/data`；`KeyManager` 在写入前自动创建 `master-key/` 子目录（若不存在） |
| 启动阻塞 | 服务启动时阻塞等待 `KeyManager.InitializationCompleted`，在密钥初始化完成前不接受任何请求 |
| 主密钥丢失恢复 | 如果主密钥丢失导致私钥解密失败，旧密钥被标记为非活跃（deactivated），自动生成新的密钥对；所有基于旧密钥签发的 JWT 将失效。该场景视为严重安全事件，必须记录 **Error 级别日志**（不是 Warning），便于在 Loki 仪表盘上立即识别并触发运维介入审计主密钥来源 |
| JWKS 速率限制 | JWKS 端点配置独立的速率限制器（FixedWindow 策略，60 次/分钟），防止公钥查询被滥用。触发拒绝时输出 Warning 日志，含客户端 IP |
| JWKS 多密钥返回 | JWKS 端点返回所有未过期密钥（含已停用但未过期的），确保密钥轮换后旧 token 在过期前仍可验证。`IssuerSigningKeyResolver` 同样使用 `GetValidKeysAsync()`，JWT 库按 `kid` 自动匹配 |
