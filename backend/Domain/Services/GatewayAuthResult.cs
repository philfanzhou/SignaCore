using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain.Services;

public class GatewayAuthResult
{
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public AppRegistrationEntity? App { get; set; }

    public static GatewayAuthResult Success(AppRegistrationEntity? app = null) => new()
    {
        IsSuccess = true,
        App = app
    };

    public static GatewayAuthResult Failure(string message) => new()
    {
        IsSuccess = false,
        ErrorMessage = message
    };
}
