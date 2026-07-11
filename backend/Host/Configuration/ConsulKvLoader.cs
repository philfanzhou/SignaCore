using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace QuantumZhou.Identity.Host.Configuration;

internal sealed class ConsulKvLoader
{
    private readonly ConsulOptions _options;
    private readonly HttpMessageHandler? _handler;

    public ConsulKvLoader(ConsulOptions options, HttpMessageHandler? handler = null)
    {
        _options = options;
        _handler = handler;
    }

    public ConsulKvLoadResult Load()
    {
        var snapshot = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var prefixes = BuildPrefixes(_options).ToArray();

        using var client = CreateClient();
        foreach (var prefix in prefixes)
        {
            foreach (var payload in FetchPrefix(client, prefix))
            {
                Merge(snapshot, FlattenJson(payload));
            }
        }

        return new ConsulKvLoadResult(snapshot, prefixes);
    }

    internal static IReadOnlyList<string> BuildPrefixes(ConsulOptions options)
    {
        return new[]
        {
            $"{options.KvPrefix}/_global",
            $"{options.KvPrefix}/_shared/{options.Profile}",
            $"{options.KvPrefix}/{options.ServiceName}/{options.Profile}"
        };
    }

    internal static Dictionary<string, string?> FlattenJson(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Consul KV value must be a JSON object.");
        }

        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        FlattenElement(document.RootElement, prefix: null, result);
        return result;
    }

    private static void FlattenElement(JsonElement element, string? prefix, IDictionary<string, string?> target)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    var childPrefix = string.IsNullOrEmpty(prefix) ? property.Name : $"{prefix}:{property.Name}";
                    FlattenElement(property.Value, childPrefix, target);
                }
                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    FlattenElement(item, $"{prefix}:{index}", target);
                    index++;
                }
                break;

            case JsonValueKind.String:
                target[prefix ?? string.Empty] = element.GetString();
                break;

            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                target[prefix ?? string.Empty] = element.GetRawText();
                break;

            case JsonValueKind.Null:
                target[prefix ?? string.Empty] = null;
                break;

            default:
                target[prefix ?? string.Empty] = element.GetRawText();
                break;
        }
    }

    private IEnumerable<string> FetchPrefix(HttpClient client, string prefix)
    {
        var requestUri = $"v1/kv/{prefix}?recurse=true";
        for (var attempt = 1; attempt <= Math.Max(1, _options.RetryCount); attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            if (!string.IsNullOrWhiteSpace(_options.Token))
            {
                request.Headers.Add("X-Consul-Token", _options.Token);
            }

            try
            {
                using var response = client.Send(request);
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return Array.Empty<string>();
                }

                response.EnsureSuccessStatusCode();
                using var stream = response.Content.ReadAsStream();
                using var document = JsonDocument.Parse(stream);
                if (document.RootElement.ValueKind != JsonValueKind.Array)
                {
                    return Array.Empty<string>();
                }

                var payloads = new List<string>();
                foreach (var item in document.RootElement.EnumerateArray())
                {
                    if (!item.TryGetProperty("Value", out var valueElement) || valueElement.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }

                    var base64 = valueElement.GetString();
                    if (string.IsNullOrWhiteSpace(base64))
                    {
                        continue;
                    }

                    payloads.Add(Encoding.UTF8.GetString(Convert.FromBase64String(base64)));
                }

                return payloads;
            }
            catch when (attempt < Math.Max(1, _options.RetryCount))
            {
                System.Threading.Thread.Sleep(250 * attempt);
            }
        }

        throw new InvalidOperationException($"Failed to load Consul KV prefix: {prefix}");
    }

    private HttpClient CreateClient()
    {
        var baseUri = new UriBuilder("http", _options.Host, _options.Port).Uri;
        return _handler == null
            ? new HttpClient { BaseAddress = baseUri, Timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs) }
            : new HttpClient(_handler, disposeHandler: false) { BaseAddress = baseUri, Timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs) };
    }

    private static void Merge(IDictionary<string, string?> target, IDictionary<string, string?> incoming)
    {
        foreach (var (key, value) in incoming)
        {
            target[key] = value;
        }
    }
}

internal sealed record ConsulKvLoadResult(
    Dictionary<string, string?> Snapshot,
    IReadOnlyList<string> Prefixes);
