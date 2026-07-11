using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.CommandLine;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Steeltoe.Discovery.Consul;

namespace QuantumZhou.Identity.Host.Configuration;

/// <summary>
/// Consul 集成扩展方法。封装 Steeltoe 调用 + 降级逻辑。
/// </summary>
public static class ProgramConsulExtensions
{
    /// <summary>
    /// 添加 Consul 配置源。
    /// 同时把 CONSUL_TOKEN 环境变量注入到 "Consul:Token" 配置节，
    /// 供后续 Steeltoe 内置 ConsulOptions 读取（ACL token 传递）。
    /// </summary>
    public static IConfigurationBuilder AddConsulIfEnabled(
        this IConfigurationBuilder builder,
        IConfiguration config)
    {
        var opts = ConsulOptions.Bind(config);
        var prefixes = ConsulKvLoader.BuildPrefixes(opts);
        StartupDiagnosticsFormatter.WriteBootstrap(
            $"Consul KV load begin: Address={opts.Host}:{opts.Port}, Prefixes={StartupDiagnosticsFormatter.SummarizePrefixes(prefixes)}, TimeoutMs={opts.TimeoutMs}, RetryCount={opts.RetryCount}, Cache={opts.EnableCache}, Token={StartupDiagnosticsFormatter.MaskSecret(opts.Token)}");

        // 把 CONSUL_TOKEN 注入到 "Consul:Token" 配置节，供 Steeltoe 内置 ConsulOptions 读取。
        // 此处注入到 IConfigurationBuilder，后续 AddConsulDiscoveryIfEnabled 可从 IConfiguration 读到。
        if (!string.IsNullOrEmpty(opts.Token))
        {
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Consul:Token"] = opts.Token
            });
        }

        var cacheService = new ConsulCacheService(opts.CacheDirectory, logger: null);
        try
        {
            var result = new ConsulKvLoader(opts).Load();
            InsertSnapshotBeforeEnvironmentSources(builder, result.Snapshot);
            if (opts.EnableCache && result.Snapshot.Count > 0)
            {
                cacheService.Save(result.Snapshot);
            }
            ConsulRuntimeState.Instance.MarkLoaded("Consul", result.Snapshot.Count, result.Prefixes, opts.CacheDirectory);
            StartupDiagnosticsFormatter.WriteBootstrap(
                $"Consul KV load success: Source=Consul, KeyCount={result.Snapshot.Count}, Prefixes={StartupDiagnosticsFormatter.SummarizePrefixes(result.Prefixes)}, CacheDirectory={opts.CacheDirectory}");
            return builder;
        }
        catch (Exception ex)
        {
            StartupDiagnosticsFormatter.WriteBootstrap(
                $"Consul KV load failed: Address={opts.Host}:{opts.Port}, Prefixes={StartupDiagnosticsFormatter.SummarizePrefixes(prefixes)}, Error={StartupDiagnosticsFormatter.SummarizeError(ex.Message)}");
            if (opts.EnableCache)
            {
                try
                {
                    var cached = cacheService.Load();
                    if (cached != null && cached.Count > 0)
                    {
                        InsertSnapshotBeforeEnvironmentSources(builder, cached);
                        ConsulRuntimeState.Instance.MarkFallback("Cache", ex.Message, cached.Count, prefixes, opts.CacheDirectory);
                        StartupDiagnosticsFormatter.WriteBootstrap(
                            $"Consul KV fallback: Source=Cache, KeyCount={cached.Count}, CacheDirectory={opts.CacheDirectory}, Error={StartupDiagnosticsFormatter.SummarizeError(ex.Message)}");
                        return builder;
                    }
                }
                catch (Exception cacheEx)
                {
                    ConsulRuntimeState.Instance.MarkFallback("AppSettings", $"{ex.Message}; cache load failed: {cacheEx.Message}", 0, prefixes, opts.CacheDirectory);
                    StartupDiagnosticsFormatter.WriteBootstrap(
                        $"Consul KV fallback: Source=AppSettings, CacheDirectory={opts.CacheDirectory}, Error={StartupDiagnosticsFormatter.SummarizeError($"{ex.Message}; cache load failed: {cacheEx.Message}")}");
                    return builder;
                }
            }

            ConsulRuntimeState.Instance.MarkFallback("AppSettings", ex.Message, 0, prefixes, opts.CacheDirectory);
            StartupDiagnosticsFormatter.WriteBootstrap(
                $"Consul KV fallback: Source=AppSettings, CacheDirectory={opts.CacheDirectory}, Error={StartupDiagnosticsFormatter.SummarizeError(ex.Message)}");
            return builder;
        }
        finally
        {
            cacheService.Dispose();
        }
    }

    /// <summary>
    /// 添加 Consul 服务发现客户端。
    /// 调用 Steeltoe.Discovery.Consul 4.2.0 的 AddConsulDiscoveryClient。
    /// 配置通过 "Consul:" 和 "Consul:Discovery:" 节绑定（Steeltoe 内置 ConsulOptions 和 ConsulDiscoveryOptions）。
    /// ACL token 已在 AddConsulIfEnabled 阶段注入到 "Consul:Token" 配置节，Steeltoe 自动绑定。
    /// </summary>
    public static IServiceCollection AddConsulDiscoveryIfEnabled(
        this IServiceCollection services,
        IConfiguration config)
    {
        services.AddSingleton(ConsulRuntimeState.Instance);

        // Steeltoe.Discovery.Consul 4.2.0：注册 Consul 服务发现客户端
        // ConsulDiscoveryOptions 自动绑定 "Consul:Discovery:" 节
        // Steeltoe 内置 ConsulOptions 自动绑定 "Consul:" 节（Host/Port/Scheme/Token）
        // Token 已在 AddConsulIfEnabled 阶段通过 AddInMemoryCollection 注入到 "Consul:Token"
        services.AddConsulDiscoveryClient();

        return services;
    }

    private static void InsertSnapshotBeforeEnvironmentSources(
        IConfigurationBuilder builder,
        IDictionary<string, string?> snapshot)
    {
        if (snapshot.Count == 0)
        {
            return;
        }

        var source = new MemoryConfigurationSource
        {
            InitialData = snapshot
        };

        var insertIndex = builder.Sources.Count;
        for (var i = 0; i < builder.Sources.Count; i++)
        {
            if (builder.Sources[i] is EnvironmentVariablesConfigurationSource ||
                builder.Sources[i] is CommandLineConfigurationSource)
            {
                insertIndex = i;
                break;
            }
        }

        builder.Sources.Insert(insertIndex, source);
    }

    /// <summary>
    /// 保存 Consul 配置缓存快照（可选，在 Build() 后调用）。
    /// 缓存已在 AddConsulIfEnabled 成功拉取 Consul KV 时即时写入，此处保留为兼容扩展点。
    /// </summary>
    public static void SaveConsulCacheIfEnabled(this IApplicationBuilder app, IConfiguration config)
    {
        _ = app;
        _ = config;
    }
}
