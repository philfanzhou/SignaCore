# RSA 密钥管理 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：test/KeyManagerTests.cs

## 单元测试

### UT-01 密钥初始化

- **Given** 数据库中无活跃密钥
- **When** KeyManager 初始化
- **Then** 生成新密钥对并存储

### UT-02 密钥轮换

- **Given** 活跃密钥即将过期
- **When** 调用 RotateKeyAsync
- **Then** 旧密钥标记为非活跃，生成新密钥对

## 遗漏的测试场景

- 主密钥丢失后的恢复测试
- 并发密钥轮换测试
