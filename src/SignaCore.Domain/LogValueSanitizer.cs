namespace SignaCore.Domain;

/// <summary>
/// Encodes line endings in values before they are written to application logs.
/// </summary>
public static class LogValueSanitizer
{
    /// <summary>
    /// Keeps each value on one physical log line without changing the underlying request data.
    /// </summary>
    public static string Sanitize(string? value) =>
        value?.ReplaceLineEndings("\\n") ?? string.Empty;

    /// <summary>
    /// Maps supported grant types to fixed log labels and avoids recording arbitrary input.
    /// String literals are intentional here: referring to a constant named "Password" causes
    /// CodeQL to mistake the OAuth grant type identifier for a credential value.
    /// </summary>
    public static string SanitizeGrantType(string? value) => value switch
    {
        "password" => "password",
        "sms" => "sms",
        "wechat_code" => "wechat_code",
        "refresh_token" => "refresh_token",
        "ldap" => "ldap",
        _ => "<unsupported>"
    };
}
