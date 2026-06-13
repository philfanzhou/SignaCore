# 过期数据自动清理 — 测试计划 (TESTS)

测试工具：xUnit + Moq
现有测试文件：test/CleanupWorkerTests.cs

## 单元测试

### UT-01 清理执行

- **Given** 存在过期数据
- **When** CleanupWorker 执行清理
- **Then** 过期数据被清理，服务继续运行

### UT-02 清理失败不中断

- **Given** 清理过程中发生异常
- **When** CleanupWorker 执行
- **Then** 记录错误日志，等待下次执行
