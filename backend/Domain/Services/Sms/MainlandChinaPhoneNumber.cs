using System.Text.RegularExpressions;

namespace QuantumZhou.Identity.Domain.Services.Sms;

public static partial class MainlandChinaPhoneNumber
{
    public static bool TryNormalize(string? value, out string phoneE164)
    {
        var compact = NonPhoneCharacters().Replace(value?.Trim() ?? string.Empty, string.Empty);
        if (compact.StartsWith("0086", StringComparison.Ordinal)) compact = "+86" + compact[4..];
        else if (compact.StartsWith("86", StringComparison.Ordinal) && !compact.StartsWith("+", StringComparison.Ordinal)) compact = "+" + compact;
        else if (compact.Length == 11) compact = "+86" + compact;

        if (MainlandMobile().IsMatch(compact))
        {
            phoneE164 = compact;
            return true;
        }

        phoneE164 = string.Empty;
        return false;
    }

    public static string Normalize(string value) =>
        TryNormalize(value, out var normalized)
            ? normalized
            : throw new ArgumentException("A valid mainland China mobile number is required.", nameof(value));

    [GeneratedRegex("[\\s()-]")]
    private static partial Regex NonPhoneCharacters();

    [GeneratedRegex("^\\+861[3-9]\\d{9}$", RegexOptions.CultureInvariant)]
    private static partial Regex MainlandMobile();
}
