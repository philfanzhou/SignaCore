namespace QuantumZhou.Identity.Host.Models;

// 管理控制台、业务网关、终端用户三个调用面共用的通用响应体。
// 不带 Admin 前缀是刻意的——改这里会同时影响 /api/admin、/api/gateway、/api/profile。

/// <summary>4xx 响应体。</summary>
public sealed record ErrorResponse(string Message);

/// <summary>无返回值的写操作的成功响应体。</summary>
public sealed record OperationResponse(bool Success, string Message);
