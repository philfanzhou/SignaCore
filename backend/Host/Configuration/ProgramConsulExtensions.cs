using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
    /// 同时把 CONSUL_TOKEN 环境变量注入到 "Consul:Token" 配置节，
    /// 供后续 Steeltoe 内置 ConsulOptions 读取（ACL token 传递）。
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

        // 把 CONSUL_TOKEN 注入到 "Consul:Token" 配置节，供 Steeltoe 内置 ConsulOptions 读取。
        // 此处注入到 IConfigurationBuilder，后续 AddConsulDiscoveryIfEnabled 可从 IConfiguration 读到。
        if (!string.IsNullOrEmpty(opts.Token))
        {
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Consul:Token"] = opts.Token
            });
        }

        // 不再内联创建 LoggerFactory（避免每次调用分配+释放资源）。
        // ConsulCacheService 构造函数支持 logger 为 null（内部使用 null 条件运算符）。
        var cacheService = new ConsulCacheService(opts.CacheDirectory, logger: null);

        // 【未来扩展点】Steeltoe.Configuration.Consul 包发布后，此处插入：
        // try { builder.AddConsul(c => { c.Host = opts.Host; c.Port = opts.Port; c.FailFast = false; ... }); }
        // catch (Exception ex) { /* 降级到缓存 */ }

        // 当前阶段：尝试从本地缓存加载（如果存在）
        if (!opts.EnableCache)
        {
            cacheService.Dispose();
            return builder;
        }

        try
        {
            var cached = cacheService.Load();
            if (cached != null && cached.Count > 0)
            {
                builder.AddInMemoryCollection(cached);
            }
            // 无缓存文件时静默降级到 appsettings（KV 加载未实现，日志由上层统一处理）
        }
        catch (Exception)
        {
            // 缓存损坏 → 跳过，用 appsettings 启动（静默处理，避免无 logger 时抛出）
        }
        finally
        {
            cacheService.Dispose();
        }

        return builder;
    }

    /// <summary>
    /// 添加 Consul 服务发现客户端（仅 CONSUL_MODE=On 时生效）。
    /// 调用 Steeltoe.Discovery.Consul 4.2.0 的 AddConsulDiscoveryClient。
    /// 配置通过 "Consul:" 和 "Consul:Discovery:" 节绑定（Steeltoe 内置 ConsulOptions 和 ConsulDiscoveryOptions）。
    /// ACL token 已在 AddConsulIfEnabled 阶段注入到 "Consul:Token" 配置节，Steeltoe 自动绑定。
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
        // Token 已在 AddConsulIfEnabled 阶段通过 AddInMemoryCollection 注入到 "Consul:Token"
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
