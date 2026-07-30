# 过期数据自动清理 — 约定与规范 (CONVENTIONS)

## 日志要求

- 清理开始：LogInformation
- 清理完成：LogInformation
- 清理失败：LogError
- 各类清理数量：LogInformation（仅在有数据被清理时）
