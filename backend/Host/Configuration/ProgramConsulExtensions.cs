using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Steeltoe.Discovery.Consul;

namespace QuantumZhou.Identity.Host.Configuration;

/// <summary>
/// Consul 集成扩展方法。封装 Steeltoe 调用 + 降级逻辑。
/// 独立模式（CONSUL_MODE=Off）下所有方法均为 no-op，不引入任何网络调用。
/// </summary>
public static class ProgramConsulExtensions
{
    /// <summary>
    /// 添加 Consul 配置源（仅 CONSUL_MODE=On 时生效）。
    /// 当前阶段：从本地缓存加载（KV 配置加载未实现，等 Steeltoe.Configuration.Consul 包发布后启用）。
    /// 独立模式：直接返回 builder，不做任何操作。
    /// </summary>
    public static IConfigurationBuilder AddConsulIfEnabled(
        this IConfigurationBuilder builder,
        IConfiguration config)
    {
        if (!ConsulOptions.IsEnabled(config))
        {
            return builder;
        }

        var opts = ConsulOptions.Bind(config);
        var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var logger = loggerFactory.CreateLogger<ConsulCacheService>();
        var cacheService = new ConsulCacheService(opts.CacheDirectory, logger);

        // 【未来扩展点】Steeltoe.Configuration.Consul 包发布后，此处插入：
        // try { builder.AddConsul(c => { c.Host = opts.Host; c.Port = opts.Port; c.FailFast = false; ... }); }
        // catch (Exception ex) { logger.LogError(ex, "Consul unreachable"); /* 降级到缓存 */ }

        // 当前阶段：尝试从本地缓存加载（如果存在）
        if (!opts.EnableCache)
        {
            logger.LogWarning(
                "Consul mode is On but cache is disabled. No KV config source available " +
                "(Steeltoe.Configuration.Consul package not yet published). " +
                "Falling back to appsettings.json only.");
            loggerFactory.Dispose();
            return builder;
        }

        try
        {
            var cached = cacheService.Load();
            if (cached != null && cached.Count > 0)
            {
                builder.AddInMemoryCollection(cached);
                logger.LogWarning(
                    "Consul mode is On, using local cache ({Count} keys) as config source. " +
                    "KV live load not yet implemented (Steeltoe.Configuration.Consul package not published).",
                    cached.Count);
            }
            else
            {
                logger.LogWarning(
                    "Consul mode is On but no cache file found at {CachePath}. " +
                    "KV live load not yet implemented. Using appsettings.json only.",
                    opts.CacheDirectory);
            }
        }
        catch (Exception ex)
        {
            // 缓存损坏 → 跳过，用 appsettings 启动
            logger.LogCritical(ex,
                "Consul cache file is corrupted at {CachePath}. Skipping cache, using appsettings.json.",
                opts.CacheDirectory);
        }
        finally
        {
            cacheService.Dispose();
            loggerFactory.Dispose();
        }

        return builder;
    }

    /// <summary>
    /// 添加 Consul 服务发现客户端（仅 CONSUL_MODE=On 时生效）。
    /// 调用 Steeltoe.Discovery.Consul 4.2.0 的 AddConsulDiscoveryClient。
    /// 配置通过 "Consul:" 和 "Consul:Discovery:" 节绑定（Steeltoe 内置 ConsulOptions 和 ConsulDiscoveryOptions）。
    /// 独立模式：直接返回 services，不做任何操作。
    /// </summary>
    public static IServiceCollection AddConsulDiscoveryIfEnabled(
        this IServiceCollection services,
        IConfiguration config)
    {
        if (!ConsulOptions.IsEnabled(config))
        {
            return services;
        }

        // Steeltoe.Discovery.Consul 4.2.0：注册 Consul 服务发现客户端
        // ConsulDiscoveryOptions 自动绑定 "Consul:Discovery:" 节
        // Steeltoe 内置 ConsulOptions 自动绑定 "Consul:" 节（Host/Port/Scheme/Token）
        services.AddConsulDiscoveryClient();

        return services;
    }

    /// <summary>
    /// 保存 Consul 配置缓存快照（可选，在 Build() 后调用）。
    /// 当前阶段为 no-op：因为 KV 加载未实现，没有数据可缓存。
    /// 未来 KV 包启用后，从 IConfigurationRoot 提取 Consul 来源的配置写入 cache.json。
    /// </summary>
    public static void SaveConsulCacheIfEnabled(this IApplicationBuilder app, IConfiguration config)
    {
        if (!ConsulOptions.IsEnabled(config))
        {
            return;
        }

        // 当前阶段 no-op（无 KV 加载源，没有数据可缓存）
        // 未来扩展：
        // var opts = ConsulOptions.Bind(config);
        // var cacheService = new ConsulCacheService(opts.CacheDirectory);
        // var snapshot = ExtractConsulSnapshot(configRoot);
        // cacheService.Save(snapshot);
    }
}
