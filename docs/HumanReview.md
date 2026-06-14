# HumanReview — QuantumZhou.Identity

> 代码审查发现项，按优先级排列。已解决项必须移除。

## P0 — 必须修复

| ID | 问题 | 位置 | 状态 |
|----|------|------|------|
| HR-01 | OTP 硬编码绕过码 "666666"，任何请求可绕过 OTP 验证 | SmsValidator.cs:44-46 | 待修复 |
| HR-02 | Admin 引导密码明文存储于 appsettings.json | appsettings.json:70-72 | 待修复 |
| HR-03 | Teacher Portal AppId/AppSecret 硬编码于 Program.cs | Program.cs:518-519 | 待修复 |
| HR-04 | SQL 注入风险 — 字符串插值拼接 SQL | Program.cs:354,364,430-437 | 待修复 |
| HR-05 | JWKS 仅返回活跃密钥，密钥轮换导致所有 token 失效 | Program.cs:638-655 | 待修复 |
| HR-06 | AppSecret 通过 HTTP Header 传输 | GatewayController.cs:14-15 | 待修复 |

## P1 — 应尽快修复

| ID | 问题 | 位置 | 状态 |
|----|------|------|------|
| HR-07 | 多处全表加载 + 内存过滤 | EfCoreRepositories.cs | 待修复 |
| HR-08 | AdminController.GetUsers N+1 查询 | AdminController.cs | 待修复 |
| HR-09 | LoggingSmsSender 明文记录 OTP | LoggingSmsSender.cs | 待修复 |
| HR-10 | RateLimitingInterceptor 使用 Peer（含端口）作为客户端 ID，限流失效 | RateLimitingInterceptor.cs | 待修复 |
| HR-11 | CORS 未配置来源时 AllowAnyOrigin | Program.cs | 待修复 |
| HR-12 | CallbackService 允许任意 Claim 注入 | CallbackService.cs | 待修复 |
| HR-13 | GatewayValidationService 返回空 AccountEntity，语义不清晰 | GatewayValidationService.cs | 待修复 |
| HR-14 | RegisterCallback 未验证 CallbackUrl 格式 | AuthServiceImpl.cs | 待修复 |
