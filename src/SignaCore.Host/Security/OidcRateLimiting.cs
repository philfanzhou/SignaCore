using System.Text;
using Microsoft.Extensions.Caching.Memory;
using SignaCore.Database;
using SignaCore.Database.Repositories;

namespace SignaCore.Host.Security;

/// <summary>
/// The named rate-limit policies of the interactive OIDC endpoint classes (issue #304) and the
/// partition-key resolution they share.
/// <para>
/// The budgets are the <c>IdentityConstants.Oidc*RateLimitPerMinute</c> constants — fixed
/// single-process windows, no queue. Partitioning follows the contract: a resolved registered
/// client gets its own bounded <c>client:{appId}</c> partition; everything else — unknown
/// clients, malformed traffic, endpoints without a client identity — falls into the bounded
/// source-network partition <c>ip:{remote address}</c>. No attacker-controlled raw value
/// (<c>state</c>, <c>nonce</c>, <c>redirect_uri</c>, username, code, token, handle) takes part
/// in the key, so the partition count is bounded by the registration count plus the source
/// address.
/// </para>
/// <para>
/// The limiter middleware runs before client authentication and before any controller work, so
/// the expensive parts (client secret verification, BCrypt password checks, one-time-artifact
/// consumption) sit behind the budget: a rejected request consumes nothing and counts no
/// failure. Enforcement is per process; the cross-replica budget stays with the #71 tracker.
/// </para>
/// </summary>
public static class OidcRateLimitPolicies
{
    public const string Authorize = "oidc-authorize";
    public const string Login = "oidc-login";
    public const string Token = "oidc-token";
    public const string UserInfo = "oidc-userinfo";
    public const string Logout = "oidc-logout";
    public const string Revoke = "oidc-revoke";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Authorize,
        Login,
        Token,
        UserInfo,
        Logout,
        Revoke
    };

    /// <summary>The <c>HttpContext.Items</c> key carrying a resolved registered client id.</summary>
    public const string RegisteredClientItemKey = "signacore.oidc.rate-limit.registered-client";

    /// <summary>The interactive endpoint classes this contract covers.</summary>
    public static readonly IReadOnlySet<string> Endpoints = new HashSet<string>(StringComparer.Ordinal)
    {
        "/oauth2/authorize",
        "/oauth2/login",
        "/oauth2/token",
        "/oauth2/userinfo",
        "/oauth2/logout",
        "/oauth2/logout/requests",
        "/oauth2/revoke"
    };

    public static bool IsInteractiveEndpoint(PathString path) =>
        Endpoints.Contains(path.Value ?? string.Empty);

    /// <summary>
    /// The fixed overload answer shared by every interactive OIDC endpoint class. The body names
    /// no partition key, no request value, and no endpoint detail, and the response never
    /// redirects anywhere.
    /// </summary>
    public const string RejectionBody =
        """{"error":"temporarily_unavailable","error_description":"The service is temporarily busy. Please try again later."}""";

    /// <summary>
    /// The synchronous partition key of one request: <c>client:{appId}</c> for a resolved
    /// registered client, otherwise the source-network partition. Attacker-controlled protocol
    /// values never enter the key.
    /// </summary>
    public static string PartitionKey(HttpContext httpContext)
    {
        if (httpContext.Items.TryGetValue(RegisteredClientItemKey, out var resolved)
            && resolved is string appId
            && appId.Length > 0)
        {
            return "client:" + appId;
        }

        return SourceNetworkKey(httpContext);
    }

    public static string SourceNetworkKey(HttpContext httpContext) =>
        "ip:" + (httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
    /// <summary>
    /// Reads one client id candidate from the transport-side carriers only: the query string,
    /// the Basic authorization header, or — for token and revoke only — the cached form body's
    /// <c>client_id</c> field. Logout preparation retains its existing query/Basic candidate
    /// policy: post credentials authenticate later, but do not select a client partition here.
    /// Login and logout bodies are never read by this resolver. Returns
    /// no value when the candidate is absent or of an unbounded shape. A failed bounded-form
    /// gate skips every carrier — no candidate is trustworthy and no client row is queried, so
    /// the request falls into the source-network partition.
    /// </summary>
    public static async Task<string?> ReadClientIdCandidateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (BoundedOidcFormReadingMiddleware.IsFailed(httpContext))
        {
            return null;
        }

        var queryId = httpContext.Request.Query["client_id"].ToString();
        if (IsPlausibleClientId(queryId))
        {
            return queryId;
        }

        var header = httpContext.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)
            && TryReadBasicClientId(header["Basic ".Length..], out var basicId))
        {
            return basicId;
        }

        var path = httpContext.Request.Path.Value ?? string.Empty;
        if (path == "/oauth2/token" || path == "/oauth2/revoke")
        {
            // The bounded-form gate already parsed and cached the body for these POSTs; reusing
            // the cached form here is the only form read this pipeline ever performs.
            if (BoundedOidcFormReadingMiddleware.GetStatus(httpContext) == OidcBoundedFormStatus.Parsed)
            {
                var cachedId = httpContext.Request.Form["client_id"].ToString();
                if (IsPlausibleClientId(cachedId))
                {
                    return cachedId;
                }

                return null;
            }

            if (httpContext.Request.HasFormContentType)
            {
                var form = await httpContext.Request.ReadFormAsync(cancellationToken);
                var formId = form["client_id"].ToString();
                if (IsPlausibleClientId(formId))
                {
                    return formId;
                }
            }
        }

        return null;
    }

    /// <summary>The client id shape is bounded before it may touch the cache or the database.</summary>
    public static bool IsPlausibleClientId(string? clientId) =>
        clientId is { Length: > 0 and <= 128 }
        && clientId.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    /// <summary>
    /// Decodes the Basic authorization payload (<c>base64(client_id:client_secret)</c>) and
    /// returns the client id half, shape-checked. The secret half is never materialized into a
    /// partition key or a log.
    /// </summary>
    public static bool TryReadBasicClientId(string payload, out string clientId)
    {
        clientId = string.Empty;
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(payload.Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        // Bound the decode before allocating a string from it.
        if (decoded is not { Length: > 0 and <= 1024 })
        {
            return false;
        }

        var separator = Array.IndexOf(decoded, (byte)':');
        if (separator <= 0)
        {
            return false;
        }

        var candidate = Encoding.ASCII.GetString(decoded, 0, separator);
        if (!IsPlausibleClientId(candidate))
        {
            return false;
        }

        clientId = candidate;
        return true;
    }
}

/// <summary>
/// Resolves the registered-client partition ahead of the rate-limiting middleware: the policy
/// factory runs synchronously inside the limiter, so the asynchronous registration read happens
/// here, once per uncached client id, behind a size-bounded cache. Only the six interactive
/// endpoint classes are inspected; every other request passes through untouched.
/// </summary>
public sealed class OidcClientPartitionResolverMiddleware(
    RequestDelegate next,
    IMemoryCache cache,
    IServiceScopeFactory scopeFactory)
{
    public async Task InvokeAsync(HttpContext httpContext)
    {
        if (OidcRateLimitPolicies.IsInteractiveEndpoint(httpContext.Request.Path))
        {
            var candidate = await OidcRateLimitPolicies.ReadClientIdCandidateAsync(
                httpContext,
                httpContext.RequestAborted);
            if (candidate is not null)
            {
                var cacheKey = "oidc-rate-limit-client:" + candidate;
                if (cache.TryGetValue(cacheKey, out bool registered) && registered)
                {
                    httpContext.Items[OidcRateLimitPolicies.RegisteredClientItemKey] = candidate;
                }
                else if (!cache.TryGetValue(cacheKey, out _))
                {
                    registered = await IsRegisteredAsync(candidate, httpContext.RequestAborted);
                    cache.Set(
                        cacheKey,
                        registered,
                        new MemoryCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30),
                            Size = 1
                        });
                    if (registered)
                    {
                        httpContext.Items[OidcRateLimitPolicies.RegisteredClientItemKey] = candidate;
                    }
                }
            }
        }

        await next(httpContext);
    }

    private async Task<bool> IsRegisteredAsync(string clientId, CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAppRegistrationRepository>();
        var application = await repository.GetByAppIdAsync(clientId, cancellationToken);
        return application is not null;
    }
}
