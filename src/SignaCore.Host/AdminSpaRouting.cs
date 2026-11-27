namespace SignaCore.Host;

/// <summary>
/// Decides whether a request belongs to the admin console SPA.
/// <para>
/// The console is served by a lowest-priority fallback endpoint (<c>{**path}</c>), which routing
/// selects only when no more specific endpoint matched, so a registered API route can never be
/// swallowed by it. The prefix check below is the second line of defence for API-shaped paths that
/// are not mapped — <c>/api/does-not-exist</c> should 404 as an API, not render the console.
/// </para>
/// </summary>
public static class AdminSpaRouting
{
    private static readonly string[] NonSpaPrefixes =
        ["/api", "/oauth2", "/.well-known", "/health", "/metrics", "/management"];

    /// <summary>
    /// Decides whether the normal host's SPA fallback endpoint should serve the console for a
    /// request. The fallback is itself a mapped endpoint (<c>{**path}</c>), reached only after
    /// routing found no more specific match, so only the port and the non-SPA prefix guards
    /// apply. A declined request is answered 404 so API-shaped and management paths keep their
    /// own contract instead of rendering the console.
    /// </summary>
    public static bool ShouldServeSpaFallback(HttpContext context, int httpPort)
    {
        if (context.Connection.LocalPort != httpPort)
        {
            return false;
        }

        return IsSpaPath(context.Request.Path);
    }

    private static bool IsSpaPath(PathString path) =>
        !NonSpaPrefixes.Any(prefix => path.StartsWithSegments(prefix));
}
