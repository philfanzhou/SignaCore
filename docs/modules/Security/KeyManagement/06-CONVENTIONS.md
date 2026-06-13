# RSA 密钥管理 — 约定与规范 (CONVENTIONS)

## 命名约定

- 主密钥文件：`master-key/master-key.json`
- 环境变量：`RSA_MASTER_KEY`
- JWKS kid：GUID 格式

## 日志要求

- 密钥加载：LogInformation
- 密钥轮换：LogInformation
- 主密钥丢失：LogWarning
- 解密失败：LogWarning
