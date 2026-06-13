# Human Review

> 仅保留本轮结束后仍需人工确认/决策的事项。已完成项和历史记录不在此保留。

## 1. 仍需人工确认事项

### HR-01: SmsValidator 硬编码 bypass code

- **问题**：`SmsValidator.ValidateAsync` 中硬编码了 bypass code `"666666"`，任何使用该验证码的请求都会直接通过验证，跳过 OTP 验证
- **已核查证据**：`backend/Domain/Validators/SmsValidator.cs` — `const string bypassCode = "666666"; var verified = request.Code == bypassCode;`，无配置项控制，无测试覆盖
- **为何仍需人工**：无法确定是开发调试用的临时代码还是有意为之的测试入口
- **建议下一步**：确认 bypass code 用途；如果是调试遗留，应移除或改为可配置项

### HR-02: GatewayValidationService 返回空 AccountEntity

- **问题**：`GatewayValidationService.ValidateAsync` 成功时返回 `ValidationResult.Success(new AccountEntity { Id = Guid.Empty }, "Gateway")`
- **已核查证据**：`AuthServiceImpl.ValidateGatewayAsync` 仅检查 `appValidation.IsSuccess`，不使用返回的 Account
- **为何仍需人工**：返回空 AccountEntity 是为了复用 ValidationResult 类型，但语义不清晰
- **建议下一步**：考虑是否应引入专用的 GatewayValidationResult 类型

### HR-03: RegisterCallback 未验证 CallbackUrl 格式

- **问题**：`AuthServiceImpl.RegisterCallback` 未调用 `CallbackUrlValidator.Validate()`，而 `CallbackService.FetchExternalClaimsAsync` 在实际回调时才验证
- **已核查证据**：RegisterCallback 方法无 URL 验证；CallbackService 在回调时验证 URL
- **为何仍需人工**：可能是设计选择（注册时不限制，使用时才验证），也可能是遗漏
- **建议下一步**：确认是否应在注册时就验证 CallbackUrl 格式

### HR-04: AdminController 和 GatewayController 内存分页

- **问题**：先 `ToListAsync()` 加载到内存，再在内存中分页
- **已核查证据**：原因是 EF Core 不支持在 Select 中嵌套子查询后分页
- **为何仍需人工**：当前数据量可能不大，但大数据量下会有性能问题
- **建议下一步**：评估当前数据量是否需要优化为数据库层面分页

### HR-05: appsettings.json 中 AdminBootstrap 密码硬编码

- **问题**：`appsettings.json` 中 `AdminBootstrap:Password` 默认值为 `Admin@2026`，明文存储在配置文件中
- **已核查证据**：`backend/Host/appsettings.json`
- **为何仍需人工**：可能是开发环境默认值，生产环境应通过环境变量覆盖
- **建议下一步**：确认生产环境是否通过环境变量或 secrets 管理覆盖此值

### HR-06: Teacher Portal 测试应用硬编码

- **问题**：`Program.cs` 中硬编码了 Teacher Portal 测试应用的 AppId 和 AppSecret，每次启动时检查并创建
- **已核查证据**：`backend/Host/Program.cs` 中硬编码的测试凭证
- **为何仍需人工**：可能是开发/测试环境的便利代码，生产环境不应包含
- **建议下一步**：确认是否应将测试应用初始化移至迁移脚本或管理 API

### HR-07: docs/Database.md 处置

- **问题**：`docs/Database.md` 已添加过时声明，但与 `docs/database/` 目录内容重复且过时
- **建议下一步**：确认是否直接删除 `docs/Database.md`，或继续保留带过时声明
