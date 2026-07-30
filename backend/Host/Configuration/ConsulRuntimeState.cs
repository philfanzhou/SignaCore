using System;
using System.Collections.Generic;

namespace QuantumZhou.Identity.Host.Configuration;

public sealed class ConsulRuntimeState
{
    private readonly object _sync = new();

    public static ConsulRuntimeState Instance { get; } = new();

    public bool Enabled { get; private set; }
    public string Mode { get; private set; } = "Off";
    public string Source { get; private set; } = "AppSettings";
    public string? LastError { get; private set; }
    public int KeyCount { get; private set; }
    public DateTimeOffset? LastLoadedAt { get; private set; }
    public DateTimeOffset? LastSuccessfulLoadAt { get; private set; }
    public IReadOnlyList<string> LoadedPrefixes { get; private set; } = Array.Empty<string>();
    public string CacheDirectory { get; private set; } = string.Empty;

    private ConsulRuntimeState()
    {
    }

    public void MarkDisabled()
    {
        lock (_sync)
        {
            Enabled = false;
            Mode = "Off";
            Source = "AppSettings";
            LastError = null;
            KeyCount = 0;
            LastLoadedAt = null;
            LastSuccessfulLoadAt = null;
            LoadedPrefixes = Array.Empty<string>();
            CacheDirectory = string.Empty;
        }
    }

    public void MarkLoaded(string source, int keyCount, IReadOnlyList<string> prefixes, string cacheDirectory)
    {
        lock (_sync)
        {
            Enabled = true;
            Mode = "On";
            Source = source;
            LastError = null;
            KeyCount = keyCount;
            LastLoadedAt = DateTimeOffset.UtcNow;
            LastSuccessfulLoadAt = LastLoadedAt;
            LoadedPrefixes = prefixes;
            CacheDirectory = cacheDirectory;
        }
    }

    public void MarkFallback(string source, string? error, int keyCount, IReadOnlyList<string> prefixes, string cacheDirectory)
    {
        lock (_sync)
        {
            Enabled = true;
            Mode = "On";
            Source = source;
            LastError = error;
            KeyCount = keyCount;
            LastLoadedAt = DateTimeOffset.UtcNow;
            LoadedPrefixes = prefixes;
            CacheDirectory = cacheDirectory;
        }
    }

    public void MarkCacheInvalidated()
    {
        lock (_sync)
        {
            if (Enabled)
            {
                Source = "AppSettings";
                KeyCount = 0;
                LastLoadedAt = DateTimeOffset.UtcNow;
            }
        }
    }

    public Dictionary<string, object?> Snapshot()
    {
        lock (_sync)
        {
            return new Dictionary<string, object?>
            {
                ["enabled"] = Enabled,
                ["mode"] = Mode,
                ["source"] = Source,
                ["keyCount"] = KeyCount,
                ["lastLoadedAt"] = LastLoadedAt,
                ["lastSuccessfulLoadAt"] = LastSuccessfulLoadAt,
                ["lastError"] = LastError,
                ["cacheDirectory"] = CacheDirectory,
                ["loadedPrefixes"] = LoadedPrefixes
            };
        }
    }
}
