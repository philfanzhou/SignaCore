namespace SignaCore.Domain.Models;

/// <summary>
/// A redirect URI in its registration-time canonical form. Request values must be compared to
/// <see cref="Value"/> with ordinal equality and must never be converted into this type.
/// </summary>
public sealed class OidcRedirectUri
{
    internal OidcRedirectUri(string value)
    {
        Value = value;
    }

    public string Value { get; }
}
