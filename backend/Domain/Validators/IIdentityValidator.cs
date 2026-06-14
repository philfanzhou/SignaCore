using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain.Validators
{
    public interface IIdentityValidator
    {
        string GrantType { get; }
        Task<ValidationResult> ValidateAsync(ValidationRequest request);
    }

    public class ValidationRequest
    {
        public string GrantType { get; set; } = string.Empty;
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Phone { get; set; }
        public string? Code { get; set; }
        public string? WechatCode { get; set; }
        public string? RefreshToken { get; set; }
        public string? AppId { get; set; }
        public string? AppSecret { get; set; }
    }

    public class ValidationResult
    {
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public AccountEntity? Account { get; set; }
        public string? AuthMethod { get; set; }
        public string? DisplayName { get; set; }

        public static ValidationResult Success(AccountEntity account, string authMethod, string? displayName = null) => new()
        {
            IsSuccess = true,
            Account = account,
            AuthMethod = authMethod,
            DisplayName = displayName
        };

        public static ValidationResult Failure(string message) => new()
        {
            IsSuccess = false,
            ErrorMessage = message
        };
    }
}

namespace QuantumZhou.Identity.Domain.Services
{
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
}