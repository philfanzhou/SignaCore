using System.Text.Json;
using System.Text.Json.Nodes;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Converts a legacy configuration section back into the canonical JSON stored in
/// <c>system_settings</c>. Only used by the one-time legacy import: once the database is
/// authoritative, values move the other way.
/// </summary>
internal static class ConfigurationJsonExporter
{
    /// <summary>
    /// Returns the JSON form of <paramref name="section"/>, or <c>null</c> when the section carries
    /// no value at all.
    /// </summary>
    public static string? Export(IConfigurationSection section)
    {
        var children = section.GetChildren().ToList();
        if (children.Count == 0)
        {
            if (section.Value is null)
            {
                return null;
            }

            // A scalar sitting where a structure is expected: environment variables commonly carry
            // "a,b,c" for what appsettings.json expresses as an array.
            return SerializeScalarAsStructure(section.Value);
        }

        var node = BuildNode(children);
        return node.ToJsonString();
    }

    private static string SerializeScalarAsStructure(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith('[') || trimmed.StartsWith('{'))
        {
            try
            {
                return JsonSettingFlattener.Canonicalize(trimmed);
            }
            catch (JsonException)
            {
                // Fall through to the comma-separated interpretation.
            }
        }

        var items = trimmed
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();

        return JsonSerializer.Serialize(items);
    }

    private static JsonNode BuildNode(IReadOnlyList<IConfigurationSection> children)
    {
        // ASP.NET Core represents arrays as children keyed "0", "1", ... — a contiguous run of those
        // is the only reliable signal that the original document held an array.
        var isArray = children
            .Select((child, index) =>
                int.TryParse(child.Key, out var parsed) && parsed == index)
            .All(matches => matches);

        if (isArray)
        {
            var array = new JsonArray();
            foreach (var child in children)
            {
                array.Add(BuildValue(child));
            }

            return array;
        }

        var jsonObject = new JsonObject();
        foreach (var child in children)
        {
            jsonObject[child.Key] = BuildValue(child);
        }

        return jsonObject;
    }

    private static JsonNode? BuildValue(IConfigurationSection section)
    {
        var children = section.GetChildren().ToList();
        if (children.Count > 0)
        {
            return BuildNode(children);
        }

        return section.Value is null ? null : JsonValue.Create(section.Value);
    }
}
