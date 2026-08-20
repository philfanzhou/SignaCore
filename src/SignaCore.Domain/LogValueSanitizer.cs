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
}
