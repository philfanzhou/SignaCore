using System.Text.RegularExpressions;

namespace SignaCore.Domain.Validators;

public interface IPasswordPolicy
{
    bool Validate(string password, out string errorMessage);
}

public partial class DefaultPasswordPolicy : IPasswordPolicy
{
    private const int MinimumLength = 8;

    [GeneratedRegex("[A-Z]")]
    private static partial Regex UppercaseRegex();

    [GeneratedRegex("[a-z]")]
    private static partial Regex LowercaseRegex();

    [GeneratedRegex("[0-9]")]
    private static partial Regex DigitRegex();

    public bool Validate(string password, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrEmpty(password))
        {
            errorMessage = "Password cannot be empty";
            return false;
        }

        if (password.Length < MinimumLength)
        {
            errorMessage = $"Password must be at least {MinimumLength} characters long";
            return false;
        }

        if (!UppercaseRegex().IsMatch(password))
        {
            errorMessage = "Password must contain at least one uppercase letter";
            return false;
        }

        if (!LowercaseRegex().IsMatch(password))
        {
            errorMessage = "Password must contain at least one lowercase letter";
            return false;
        }

        if (!DigitRegex().IsMatch(password))
        {
            errorMessage = "Password must contain at least one number";
            return false;
        }

        return true;
    }
}
