namespace SignaCore.Host.Models;

// The shared response bodies of all three call surfaces: the administration console, the business
// gateway, and end users.
// The absence of an Admin prefix is deliberate — changing anything here affects /api/admin,
// /api/gateway and /api/profile at once.

/// <summary>The body of a 4xx response.</summary>
public sealed record ErrorResponse(string Message);

/// <summary>The success body of a write operation that returns no value.</summary>
public sealed record OperationResponse(bool Success, string Message);
