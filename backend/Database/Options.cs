namespace QuantumZhou.Identity.Database;

public class JwtOptions
{
    public string Issuer { get; set; } = "QuantumZhou.Identity";
    public string Audience { get; set; } = "QuantumZhou.microservices";
    public int TokenExpirationHours { get; set; } = 2;

    public void Validate()
    {
        if (TokenExpirationHours <= 0)
        {
            throw new InvalidOperationException("TokenExpirationHours must be a positive number");
        }
        if (string.IsNullOrEmpty(Issuer))
        {
            throw new InvalidOperationException("Jwt Issuer cannot be empty");
        }
        if (string.IsNullOrEmpty(Audience))
        {
            throw new InvalidOperationException("Jwt Audience cannot be empty");
        }
    }
}

public class RefreshTokenOptions
{
    public int RefreshTokenExpirationDays { get; set; } = 7;

    public void Validate()
    {
        if (RefreshTokenExpirationDays <= 0)
        {
            throw new InvalidOperationException("RefreshTokenExpirationDays must be a positive number");
        }
    }
}
