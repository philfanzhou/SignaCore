using System.Globalization;
using System.Text.Json;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Expands a stored JSON setting into ASP.NET Core configuration keys, so
/// <c>Ldap:Directories</c> stored as a JSON array binds exactly like the appsettings.json section it
/// replaced. This mirrors what the built-in JSON configuration provider does with a file.
/// </summary>
internal static class JsonSettingFlattener
{
    public static void Flatten(
        string rootKey,
        string json,
        IDictionary<string, string?> destination)
    {
        using var document = JsonDocument.Parse(json);
        Visit(rootKey, document.RootElement, destination);
    }

    /// <summary>
    /// Validates that a value parses as JSON and returns its canonical (whitespace-free) form.
    /// </summary>
    public static string Canonicalize(string json)
    {
        using var document = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(document.RootElement);
    }

    private static void Visit(
        string prefix,
        JsonElement element,
        IDictionary<string, string?> destination)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    Visit($"{prefix}:{property.Name}", property.Value, destination);
                }

                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    Visit($"{prefix}:{index.ToString(CultureInfo.InvariantCulture)}", item, destination);
                    index++;
                }

                break;

            case JsonValueKind.Null:
                destination[prefix] = null;
                break;

            case JsonValueKind.String:
                destination[prefix] = element.GetString();
                break;

            default:
                // Numbers and booleans keep their JSON text; the configuration binder parses them
                // with the same invariant rules it applies to appsettings.json.
                destination[prefix] = element.GetRawText();
                break;
        }
    }
}
