using System.Text.Json;

namespace SignaCore.Host.Security;

/// <summary>Strict literal private-IP origins; parsing never resolves a network name.</summary>
internal static class HostedLoginHttpTestOrigins
{
    internal const string SettingKey = "security.hosted_login_http_test_origins";
    internal const string InvalidCode = "signacore.setting.http_test_origins_invalid";

    internal static bool TryParseJson(string? json, out HashSet<string> origins)
    {
        origins = new(StringComparer.Ordinal);
        if (json is null) return true;
        if (json.Length > 8192) return false;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() > 32) return false;
            foreach (var item in root.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String
                    || !TryCanonicalize(item.GetString(), out var origin)
                    || !origins.Add(origin)) return false;
            }
            return true;
        }
        catch (JsonException) { return false; }
    }

    internal static bool TryCanonicalize(string? value, out string origin) =>
        SignaCore.Domain.Validators.HostedLoginHttpTestOrigin.TryCanonicalize(value, out origin);
}
