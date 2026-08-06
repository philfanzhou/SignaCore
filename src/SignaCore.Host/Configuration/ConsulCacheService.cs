using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Consul 本地缓存读写服务。原子替换 + 损坏处理。
/// 当前阶段为占位实现（KV 加载未启用，缓存不会写入）；未来 Steeltoe KV 包启用后用于降级兜底。
/// </summary>
public sealed class ConsulCacheService : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null
    };

    private readonly string _cacheFilePath;
    private readonly string _metadataFilePath;
    private readonly string _cacheDirectory;
    private readonly ILogger<ConsulCacheService>? _logger;
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private bool _disposed;

    public ConsulCacheService(string cacheDirectory, ILogger<ConsulCacheService>? logger = null)
    {
        _cacheDirectory = cacheDirectory;
        _cacheFilePath = Path.Combine(cacheDirectory, "cache.json");
        _metadataFilePath = Path.Combine(cacheDirectory, "cache.metadata.json");
        _logger = logger;
    }

    /// <summary>
    /// 从 cache.json 读取缓存。文件不存在返回 null；损坏抛 JsonException。
    /// 线程安全：通过 SemaphoreSlim 串行化读写。
    /// </summary>
    public Dictionary<string, string?>? Load()
    {
        _semaphore.Wait();
        try
        {
            if (!File.Exists(_cacheFilePath))
            {
                return null;
            }

            var json = File.ReadAllText(_cacheFilePath);
            var result = JsonSerializer.Deserialize<Dictionary<string, string?>>(json, JsonOptions);
            return result;
        }
        catch (JsonException ex)
        {
            // 损坏 → 抛出由调用方捕获
            _logger?.LogCritical(ex,
                "Consul cache file is corrupted: {FilePath}. Remove it to recover.", _cacheFilePath);
            throw;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// 原子写入 cache.json。先写 .tmp，校验后 File.Replace 替换。
    /// 线程安全：通过 SemaphoreSlim 串行化。
    /// </summary>
    public void Save(Dictionary<string, string?> data)
    {
        _semaphore.Wait();
        try
        {
            Directory.CreateDirectory(_cacheDirectory);

            var tmpPath = _cacheFilePath + ".tmp";
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(tmpPath, json);

            // 校验 .tmp 文件可解析
            var verify = File.ReadAllText(tmpPath);
            _ = JsonSerializer.Deserialize<Dictionary<string, string?>>(verify, JsonOptions);

            // 原子替换
            if (File.Exists(_cacheFilePath))
            {
                File.Replace(tmpPath, _cacheFilePath, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tmpPath, _cacheFilePath);
            }

            // 写元数据
            var metadata = new CacheMetadata
            {
                UpdatedAt = DateTimeOffset.UtcNow,
                ConsulAddress = Environment.GetEnvironmentVariable("CONSUL_HTTP_ADDR") ?? "host.docker.internal:8500",
                KeyCount = data.Count
            };
            var metaJson = JsonSerializer.Serialize(metadata, JsonOptions);
            var metaTmp = _metadataFilePath + ".tmp";
            File.WriteAllText(metaTmp, metaJson);

            if (File.Exists(_metadataFilePath))
            {
                File.Replace(metaTmp, _metadataFilePath, destinationBackupFileName: null);
            }
            else
            {
                File.Move(metaTmp, _metadataFilePath);
            }

            _logger?.LogDebug("Consul cache saved: {Count} keys at {Path}", data.Count, _cacheFilePath);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>缓存文件是否存在。</summary>
    public bool Exists()
    {
        _semaphore.Wait();
        try
        {
            return File.Exists(_cacheFilePath);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>清空缓存（删除 cache.json 和 cache.metadata.json）。</summary>
    public void Invalidate()
    {
        _semaphore.Wait();
        try
        {
            if (File.Exists(_cacheFilePath)) File.Delete(_cacheFilePath);
            if (File.Exists(_metadataFilePath)) File.Delete(_metadataFilePath);
            _logger?.LogInformation("Consul cache invalidated: {Path}", _cacheFilePath);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _semaphore.Dispose();
            _disposed = true;
        }
    }

    private sealed class CacheMetadata
    {
        public DateTimeOffset UpdatedAt { get; set; }
        public string ConsulAddress { get; set; } = string.Empty;
        public int KeyCount { get; set; }
    }
}
