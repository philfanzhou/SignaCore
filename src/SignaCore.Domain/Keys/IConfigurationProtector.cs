namespace SignaCore.Domain.Keys;

/// <summary>
/// Protects sensitive global settings before they are written to <c>system_settings</c>.
/// <para>
/// The setting key and schema version are bound as authenticated associated data, so an envelope
/// cannot be moved from one setting to another (for example swapping a throwaway SMS key into the
/// OTP HMAC slot) without the tag failing.
/// </para>
/// </summary>
public interface IConfigurationProtector
{
    string Protect(string settingKey, string plaintext);

    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The envelope is malformed, was produced for a different setting key or schema version, or the
    /// root key does not match the one used to write it.
    /// </exception>
    string Unprotect(string settingKey, string protectedValue);
}
