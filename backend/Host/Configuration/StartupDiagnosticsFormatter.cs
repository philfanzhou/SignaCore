using System;
using System.Collections.Generic;
using System.Linq;

namespace QuantumZhou.Identity.Host.Configuration;

internal static class StartupDiagnosticsFormatter
{
    public static string MaskSecret(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "<empty>";
        }

        var trimmed = value.Trim();
        if (trimmed.Length <= 4)
        {
            return "****";
        }

        if (trimmed.Length <= 8)
        {
            return string.Concat(trimmed.AsSpan(0, 1), "***", trimmed.AsSpan(trimmed.Length - 1));
        }

        return string.Concat(trimmed.AsSpan(0, 4), "***", trimmed.AsSpan(trimmed.Length - 4));
    }

    public static string SummarizePrefixes(IEnumerable<string>? values)
    {
        if (values == null)
        {
            return "<none>";
        }

        var items = values.Where(static item => !string.IsNullOrWhiteSpace(item)).ToArray();
        return items.Length == 0 ? "<none>" : string.Join(",", items);
    }

    public static string SummarizeValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? "<empty>" : value;
    }

    public static string SummarizeError(string? error)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            return "<none>";
        }

        return error.Length <= 240 ? error : $"{error[..240]}...";
    }

    public static string SummarizePassword(string? password)
    {
        return string.IsNullOrWhiteSpace(password)
            ? "<empty>"
            : $"<masked:length={password.Length}>";
    }

    public static void WriteBootstrap(string message)
    {
        Console.WriteLine($"[BOOT] {message}");
    }
}
