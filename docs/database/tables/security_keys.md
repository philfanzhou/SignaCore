# security_keys (RSA 密钥对表)

RSA 密钥对表，用于签名 JWT。私钥使用主密钥（RSA_MASTER_KEY）经 AES-GCM 加密后存储。公钥通过 `/.well-known/jwks` 暴露给下游服务验证 JWT。

## 字段清单

| 字段名 | 类型 | 约束 | 默认值 | 说明 |
|--------|------|------|--------|------|
| id | UUID | PK | - | 主键 |
| key_id | VARCHAR(100) | NOT NULL, UNIQUE | - | 密钥唯一标识（JWKS 中的 kid） |
| public_key_exponent | VARCHAR(4096) | NOT NULL | - | RSA 公钥指数（Base64） |
| public_key_modulus | VARCHAR(2048) | NOT NULL | - | RSA 公钥模数（Base64） |
| encrypted_private_key_params | VARCHAR(4096) | NOT NULL | - | AES-GCM 加密的 RSA 私钥参数（Base64） |
| encryption_salt | VARCHAR(256) | NOT NULL | - | AES-GCM 加密盐值（Base64） |
| created_at | TIMESTAMPTZ | NOT NULL | - | 密钥创建时间 |
| expires_at | TIMESTAMPTZ | NOT NULL | - | 密钥过期时间 |
| is_active | BOOLEAN | NOT NULL | true | 是否为当前用于签名的活跃密钥 |

## 索引

| 索引名 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| IX_security_keys_key_id | key_id | UNIQUE | 密钥 ID 唯一索引 |

## 特殊说明

- 密钥寿命默认 30 天（`IdentityConstants.KeyRotationDays`），但轮换在**半衰期**（15 天）就触发，不等过期：
  `GetValidKeysAsync`（JWKS 数据源）过滤 `expires_at > now`，密钥一旦过期就不再发布，
  必须在此之前备好新密钥，否则 JWKS 会返回空数组、下游微服务全部验签失败
- 加密方式：使用 HKDF(SHA256) 从主密钥派生 AES-256 密钥，再用 AES-GCM 加密私钥
- 主密钥来源优先级：环境变量 `RSA_MASTER_KEY` > 本地文件 `data/master-key/master-key.json` > 自动生成（`master-key/` 子目录由 KeyManager 在写入前自动创建）
- 同时只有一个 `is_active = true` 的密钥
- `CleanupWorker` 定期清理过期且非活跃的密钥记录
- 如果主密钥丢失导致解密失败，`KeyManager` 会自动生成新密钥对（所有已签发的 JWT 将失效）
