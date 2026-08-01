using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain.Validators;

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

    /// <summary>短信验证码或微信 code，按 <see cref="GrantType"/> 解释。</summary>
    public string? Code { get; set; }

    public string? RefreshToken { get; set; }
    public string? AppId { get; set; }
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