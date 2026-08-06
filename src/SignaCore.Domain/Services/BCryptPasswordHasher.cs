using SignaCore.Database;

namespace SignaCore.Domain.Services;

public class PasswordHasherOptions
{
    public int WorkFactor { get; set; } = IdentityConstants.BCryptWorkFactor;
}

public class BCryptPasswordHasher : IPasswordHasher
{
    private readonly int _workFactor;

    public BCryptPasswordHasher(PasswordHasherOptions options)
    {
        _workFactor = options.WorkFactor;
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, _workFactor);
    }

    public bool VerifyPassword(string password, string hash)
    {
        return BCrypt.Net.BCrypt.Verify(password, hash);
    }
}
