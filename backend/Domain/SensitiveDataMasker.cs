namespace QuantumZhou.Identity.Domain;

/// <summary>
/// 敏感字段脱敏工具。所有写入日志（含 Loki）的手机号、OpenId 等字段必须经此工具脱敏。
/// 规则参见 docs/development/ErrorHandling.md「敏感字段脱敏」。
/// </summary>
public static class SensitiveDataMasker
{
    /// <summary>
    /// 手机号脱敏：保留前 3 + 后 4，中间用 **** 替换。例如 13812341234 → 138****1234。
    /// 长度不足 7 位时全部替换为 ****。
    /// </summary>
    public static string MaskPhone(string? phone)
    {
        if (string.IsNullOrEmpty(phone)) return string.Empty;
        if (phone.Length < 7) return "****";

        return string.Concat(phone.AsSpan(0, 3), "****", phone.AsSpan(phone.Length - 4));
    }

    /// <summary>
    /// 微信 OpenId 脱敏：保留前 4 + 后 4，中间用 **** 替换。例如 o1QxYzAbcdefghijklwxyz → o1Qx****wxyz。
    /// 长度不足 8 位时全部替换为 ****。
    /// </summary>
    public static string MaskOpenId(string? openId)
    {
        if (string.IsNullOrEmpty(openId)) return string.Empty;
        if (openId.Length < 8) return "****";

        return string.Concat(openId.AsSpan(0, 4), "****", openId.AsSpan(openId.Length - 4));
    }
}
