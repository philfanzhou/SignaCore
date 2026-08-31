namespace SignaCore.Domain.Validators;

/// <summary>A non-sensitive interactive OIDC client configuration error.</summary>
public sealed class OidcClientConfigurationException : ArgumentException
{
    public OidcClientConfigurationException(string message) : base(message)
    {
    }
}
