# RSA 密钥管理 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：
- `backend/Tests/unit/Domain/KeyManagerTests.cs`（生命周期编排，Moq）
- `backend/Tests/unit/Domain/Keys/KeyRotationTimelineTests.cs`（轮换时间线，**真实仓储**）
- `backend/Tests/unit/Domain/Keys/AesGcmPrivateKeyProtectorTests.cs`（加密格式契约）
- `backend/Tests/unit/Domain/Keys/FileMasterKeyProviderTests.cs`（主密钥来源优先级）

> 以上均属 xUnit collection `MasterKeyState`，因为它们共享进程级状态
> （环境变量 `RSA_MASTER_KEY` 与 `data/master-key/master-key.json`），并行执行会互相踩。

> `KeyRotationTimelineTests` 刻意**不用 Moq**：`KeyManagerTests` 里每个用例都把
> `GetActiveKeyAsync` 摆成自己想要的状态，于是"`NeedsKeyRotationAsync` 说该轮换时，
> `GetActiveKeyAsync` 实际会返回什么"这个跨方法契约无人覆盖——历史上的 JWKS 空窗
> bug 正是藏在这里。跨方法的时序契约必须让两个方法面对同一份真实数据。

## 单元测试

### UT-01 密钥初始化

- **Given** 数据库中无活跃密钥
- **When** KeyManager 初始化
- **Then** 生成新密钥对并存储

### UT-02 密钥轮换

- **Given** 活跃密钥剩余寿命不足总寿命的一半
- **When** 调用 RotateKeyAsync
- **Then** 所有旧密钥标记为非活跃，生成新密钥对，且二者在同一次 SaveChanges 内提交

### UT-03 JWKS 不出现空窗（回归）

- **Given** 密钥寿命内的任意一天，CleanupWorker 每 24h tick 一次
- **When** 下游微服务在两次 tick **之间**拉取 `/.well-known/jwks`
- **Then** 始终至少返回一把公钥
- 覆盖：`KeyRotationTimelineTests.Jwks_NeverReturnsEmpty_BetweenCleanupTicks`

### UT-04 轮换后不残留僵尸 active 行（回归）

- **Given** 密钥已过期后才发生轮换（例如服务停机数日后重启）
- **When** 调用 RotateKeyAsync
- **Then** 库中不存在 `is_active=true` 且已过期的行，否则 `RemoveExpiredInactiveAsync` 永远清不掉

## 遗漏的测试场景

- 主密钥丢失后的恢复测试
- 并发密钥轮换测试（多实例：当前 `_currentKey` / 校验密钥快照都是实例内存态，
  另一实例轮换后本实例不感知，直到下次重启）
