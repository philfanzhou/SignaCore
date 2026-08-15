using System.Text.Json.Serialization;

namespace SignaCore.Host.Models;

public sealed class SettingItemResponse
{
    [JsonPropertyName("key")]
    public string Key { get; set; } = string.Empty;

    [JsonPropertyName("valueType")]
    public string ValueType { get; set; } = string.Empty;

    [JsonPropertyName("isSecret")]
    public bool IsSecret { get; set; }

    /// <summary>
    /// The current value, or <c>null</c> for a secret. Secret values are never returned from
    /// settings-list APIs; the console shows only whether one is set.
    /// </summary>
    [JsonPropertyName("value")]
    public string? Value { get; set; }

    /// <summary>Whether a secret currently holds a non-empty value.</summary>
    [JsonPropertyName("hasValue")]
    public bool HasValue { get; set; }

    [JsonPropertyName("restartRequired")]
    public bool RestartRequired { get; set; }

    [JsonPropertyName("updatedAt")]
    public long? UpdatedAt { get; set; }

    [JsonPropertyName("updatedBy")]
    public string? UpdatedBy { get; set; }
}

public sealed class SettingsListResponse
{
    [JsonPropertyName("configurationVersion")]
    public int ConfigurationVersion { get; set; }

    /// <summary>The version this process is running, which may lag the stored one after a change.</summary>
    [JsonPropertyName("runningConfigurationVersion")]
    public int RunningConfigurationVersion { get; set; }

    [JsonPropertyName("restartPending")]
    public bool RestartPending { get; set; }

    [JsonPropertyName("items")]
    public IReadOnlyList<SettingItemResponse> Items { get; set; } = [];
}

public sealed class UpdateSettingsRequest
{
    /// <summary>
    /// Only the keys present here are changed. Omitting a secret leaves it untouched, which is how
    /// the console can render a form it never received the secret values for.
    /// </summary>
    [JsonPropertyName("values")]
    public Dictionary<string, string> Values { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class UpdateSettingsResponse
{
    [JsonPropertyName("configurationVersion")]
    public int ConfigurationVersion { get; set; }

    [JsonPropertyName("changedKeys")]
    public IReadOnlyList<string> ChangedKeys { get; set; } = [];

    [JsonPropertyName("restartRequired")]
    public bool RestartRequired { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}
