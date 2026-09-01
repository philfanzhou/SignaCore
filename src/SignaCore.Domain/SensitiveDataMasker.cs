namespace SignaCore.Domain;

/// <summary>
/// The masking helper for sensitive fields. Every phone number, OpenId and similar field written to
/// the logs, Loki included, has to be masked through it.
/// See the sensitive field masking rules in docs/development/ErrorHandling.md.
/// </summary>
public static class SensitiveDataMasker
{
    /// <summary>
    /// Masks a phone number: the first 3 and the last 4 characters are kept and everything between
    /// them is replaced with ****. For example, 13812341234 becomes 138****1234.
    /// Anything shorter than 7 characters is replaced with **** entirely.
    /// </summary>
    public static string MaskPhone(string? phone)
    {
        if (string.IsNullOrEmpty(phone)) return string.Empty;
        if (phone.Length < 7) return "****";

        return string.Concat(phone.AsSpan(0, 3), "****", phone.AsSpan(phone.Length - 4));
    }

    /// <summary>
    /// Masks a WeChat OpenId: the first 4 and the last 4 characters are kept and everything between
    /// them is replaced with ****. For example, o1QxYzAbcdefghijklwxyz becomes o1Qx****wxyz.
    /// Anything shorter than 8 characters is replaced with **** entirely.
    /// </summary>
    public static string MaskOpenId(string? openId)
    {
        if (string.IsNullOrEmpty(openId)) return string.Empty;
        if (openId.Length < 8) return "****";

        return string.Concat(openId.AsSpan(0, 4), "****", openId.AsSpan(openId.Length - 4));
    }
}
