using System;
using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Identity Consul 集成强类型配置类。绑定 appsettings.json "Consul:" 节。
/// 与 Steeltoe.Discovery.Consul 的内置 ConsulOptions 类（Steeltoe.Discovery.Consul.Configuration 命名空间）
/// 不冲突：本类用于应用层模式判断与缓存目录，Steeltoe 的 ConsulOptions 用于 Consul 客户端连接参数。
/// </summary>
public sealed class ConsulOptions
{
    /// <summary>Consul HTTP API 地址。默认 host.docker.internal（宿主机映射）。</summary>
    public string Host { get; set; } = "host.docker.internal";

    /// <summary>Consul HTTP API 端口。默认 8500。</summary>
    public int Port { get; set; } = 8500;

    /// <summary>注册到 Consul 的服务名。默认 SignaCore。</summary>
    public string ServiceName { get; set; } = "SignaCore";

    /// <summary>服务实例 ID。为空时由 Steeltoe 自动生成。</summary>
    public string? ServiceId { get; set; }

    /// <summary>KV 路径前缀（未来扩展：KV 配置加载）。默认 config/signacore。</summary>
    public string KvPrefix { get; set; } = "config/signacore";

    /// <summary>请求超时（毫秒）。默认 3000。</summary>
    public int TimeoutMs { get; set; } = 3000;

    /// <summary>连接重试次数。默认 3。</summary>
    public int RetryCount { get; set; } = 3;

    /// <summary>是否启用本地缓存兜底。默认 true。</summary>
    public bool EnableCache { get; set; } = true;

    /// <summary>缓存文件目录。默认 ./data/consul。</summary>
    public string CacheDirectory { get; set; } = "./data/consul";

    /// <summary>
    /// Consul ACL token（用于访问启用了 ACL 的 Consul 集群）。
    /// 受环境变量 CONSUL_TOKEN 控制。为空时表示 ACL 未启用或匿名访问。
    /// 此值会传给 Steeltoe 的 ConsulOptions.Token（Steeltoe.Discovery.Consul 内置）。
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// 当前项目固定启用 Consul 集成，不再保留 Mode 开关。
    /// </summary>
    public static bool IsEnabled(IConfiguration config)
    {
        return true;
    }

    /// <summary>
    /// 从 "Consul:" 节绑定 ConsulOptions 实例。
    /// 环境变量 CONSUL_* 优先级高于 appsettings.json（通过 __ 分隔符自动映射）。
    /// </summary>
    public static ConsulOptions Bind(IConfiguration config)
    {
        var opts = new ConsulOptions();
        config.GetSection("Consul").Bind(opts);

        // 环境变量短名覆盖（CONSUL_HTTP_ADDR 优先）
        var envHttpAddr = Environment.GetEnvironmentVariable("CONSUL_HTTP_ADDR");
        if (!string.IsNullOrWhiteSpace(envHttpAddr))
        {
            ApplyHttpAddressOverride(opts, envHttpAddr);
        }

        var envHost = Environment.GetEnvironmentVariable("CONSUL_HOST");
        if (!string.IsNullOrEmpty(envHost)) opts.Host = envHost;

        var envPort = Environment.GetEnvironmentVariable("CONSUL_PORT");
        if (int.TryParse(envPort, out var port)) opts.Port = port;

        var envServiceName = Environment.GetEnvironmentVariable("CONSUL_SERVICE_NAME");
        if (!string.IsNullOrEmpty(envServiceName)) opts.ServiceName = envServiceName;

        var envServiceId = Environment.GetEnvironmentVariable("CONSUL_SERVICE_ID");
        if (!string.IsNullOrEmpty(envServiceId)) opts.ServiceId = envServiceId;

        var envKvPrefix = Environment.GetEnvironmentVariable("CONSUL_KV_PREFIX");
        if (!string.IsNullOrEmpty(envKvPrefix)) opts.KvPrefix = envKvPrefix;

        var envTimeout = Environment.GetEnvironmentVariable("CONSUL_TIMEOUT_MS");
        if (int.TryParse(envTimeout, out var timeout)) opts.TimeoutMs = timeout;

        var envRetry = Environment.GetEnvironmentVariable("CONSUL_RETRY_COUNT");
        if (int.TryParse(envRetry, out var retry)) opts.RetryCount = retry;

        var envEnableCache = Environment.GetEnvironmentVariable("CONSUL_ENABLE_CACHE");
        if (bool.TryParse(envEnableCache, out var enableCache)) opts.EnableCache = enableCache;

        var envCacheDir = Environment.GetEnvironmentVariable("CONSUL_CACHE_DIR");
        if (!string.IsNullOrEmpty(envCacheDir)) opts.CacheDirectory = envCacheDir;

        // ACL token（启用 ACL 时必需）
        var envToken = Environment.GetEnvironmentVariable("CONSUL_TOKEN");
        if (!string.IsNullOrEmpty(envToken)) opts.Token = envToken;

        return opts;
    }

    private static void ApplyHttpAddressOverride(ConsulOptions options, string httpAddress)
    {
        var normalized = httpAddress.Trim();
        if (Uri.TryCreate($"http://{normalized}", UriKind.Absolute, out var hostPortUri))
        {
            options.Host = hostPortUri.Host;
            if (!hostPortUri.IsDefaultPort)
            {
                options.Port = hostPortUri.Port;
            }
            return;
        }

        if (Uri.TryCreate(normalized, UriKind.Absolute, out var absoluteUri) &&
            !string.IsNullOrWhiteSpace(absoluteUri.Host))
        {
            options.Host = absoluteUri.Host;
            if (!absoluteUri.IsDefaultPort)
            {
                options.Port = absoluteUri.Port;
            }
            return;
        }

        var lastColonIndex = normalized.LastIndexOf(':');
        if (lastColonIndex > 0 &&
            lastColonIndex < normalized.Length - 1 &&
            int.TryParse(normalized[(lastColonIndex + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            options.Host = normalized[..lastColonIndex];
            options.Port = port;
            return;
        }

        options.Host = normalized;
    }
}
