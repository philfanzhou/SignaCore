using System.Text;

namespace SignaCore.Database;

public static class IdentityValueNormalizer
{
    public static string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Normalize(NormalizationForm.FormC).ToUpperInvariant();
    }

    public static string? NormalizeNullable(string? value)
    {
        return value is null ? null : Normalize(value);
    }
}
