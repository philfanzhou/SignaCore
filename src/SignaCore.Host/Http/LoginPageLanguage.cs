using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace SignaCore.Host.Http;

/// <summary>
/// The two languages of the hosted login page (ADR 0006): <c>en</c> and <c>zh-CN</c>.
/// </summary>
internal enum LoginPageLanguage
{
    English,
    SimplifiedChinese
}

/// <summary>
/// Selects the hosted login page language from the <c>Accept-Language</c> request header only.
/// No query or form field, cookie, stored continuation value, or configuration key takes part, so
/// the same request shape always renders the same language. The negotiation is a pure function and
/// deliberately does not use the request-localization middleware or <c>CultureInfo</c>, so it
/// cannot change the culture of any other route.
/// </summary>
internal static class LoginPageLanguageNegotiator
{
    /// <summary>
    /// Parses every <c>Accept-Language</c> value strictly. A header that fails strict parsing or
    /// carries a quality outside 0–1 selects English. Otherwise the ranges are ordered by quality,
    /// highest first and stable for equal qualities; ranges with <c>q=0</c> are skipped; the first
    /// range that is <c>zh</c> or <c>zh-*</c> selects Simplified Chinese, and the first that is
    /// <c>en</c>, <c>en-*</c>, or <c>*</c> selects English. Language tags compare
    /// case-insensitively. With no matching range the page falls back to English.
    /// </summary>
    public static LoginPageLanguage Negotiate(StringValues acceptLanguage)
    {
        if (StringValues.IsNullOrEmpty(acceptLanguage)
            || !StringWithQualityHeaderValue.TryParseStrictList(acceptLanguage, out var ranges))
        {
            return LoginPageLanguage.English;
        }

        var ordered = new List<(string Tag, double Quality)>(ranges.Count);
        foreach (var range in ranges)
        {
            var quality = range.Quality ?? 1.0;
            if (double.IsNaN(quality) || quality < 0 || quality > 1)
            {
                return LoginPageLanguage.English;
            }

            ordered.Add((range.Value.Value ?? string.Empty, quality));
        }

        // List.Sort is not stable; OrderByDescending is, which keeps the header order between
        // ranges of equal quality.
        foreach (var (tag, quality) in ordered.OrderByDescending(range => range.Quality))
        {
            if (quality == 0)
            {
                continue;
            }

            if (IsLanguage(tag, "zh"))
            {
                return LoginPageLanguage.SimplifiedChinese;
            }

            if (tag == "*" || IsLanguage(tag, "en"))
            {
                return LoginPageLanguage.English;
            }
        }

        return LoginPageLanguage.English;
    }

    private static bool IsLanguage(string tag, string primary) =>
        tag.Equals(primary, StringComparison.OrdinalIgnoreCase)
        || (tag.Length > primary.Length
            && tag[primary.Length] == '-'
            && tag.StartsWith(primary, StringComparison.OrdinalIgnoreCase));
}
