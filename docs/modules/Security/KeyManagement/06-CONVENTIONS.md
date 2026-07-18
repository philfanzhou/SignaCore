# RSA 密钥管理 — 约定与规范 (CONVENTIONS)

## 命名约定

- 主密钥文件：`data/master-key/master-key.json`（`master-key/` 子目录由 KeyManager 在写入前自动创建）
- 环境变量：`RSA_MASTER_KEY`
- JWKS kid：GUID 格式

## 日志要求

- 密钥加载：LogInformation
- 密钥轮换：LogInformation
- 主密钥丢失：LogWarning
- 解密失败：LogWarning
