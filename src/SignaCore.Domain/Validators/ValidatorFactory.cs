using Microsoft.Extensions.Logging;

namespace SignaCore.Domain.Validators;

public class ValidatorFactory
{
    private readonly IReadOnlyDictionary<string, IIdentityValidator> _validators;
    private readonly ILogger<ValidatorFactory> _logger;

    public ValidatorFactory(IEnumerable<IIdentityValidator> validators, ILogger<ValidatorFactory> logger)
    {
        _logger = logger;
        _validators = validators.ToDictionary(v => v.GrantType);

        var registeredTypes = string.Join(", ", _validators.Keys);
        _logger.LogInformation("ValidatorFactory initialized with grant types: {GrantTypes}", registeredTypes);
    }

    public IIdentityValidator GetValidator(string grantType)
    {
        if (!_validators.TryGetValue(grantType, out var validator))
        {
            // "password" is an OAuth grant type identifier, not a password or credential value.
            // codeql[cs/cleartext-storage-of-sensitive-information]
            _logger.LogWarning("No validator found for grant type: {GrantType}, available: {AvailableTypes}",
                LogValueSanitizer.Sanitize(grantType),
                LogValueSanitizer.Sanitize(string.Join(", ", _validators.Keys)));
            throw new KeyNotFoundException($"No validator registered for grant type: {grantType}");
        }
        return validator;
    }

    public bool IsSupportedGrantType(string grantType) => _validators.ContainsKey(grantType);

    public IEnumerable<string> GetSupportedGrantTypes() => _validators.Keys;
}
