namespace SignaCore.Host;

/// <summary>
/// Decides whether a request belongs to the admin SPA branch of the pipeline.
/// <para>
/// The SPA branch is <b>terminal</b>: <c>MapWhen</c> never returns to the main pipeline, and the branch
/// ends by rewriting the path to <c>/index.html</c>. Anything routed into it by mistake therefore never
/// reaches <c>MapControllers()</c> — it silently 404s or gets HTML back. That already happened once:
/// <c>/oauth2/*</c> was added without extending the prefix list and was swallowed whole in any real
/// deployment. Tests did not catch it because <c>TestServer</c> leaves
/// <see cref="ConnectionInfo.LocalPort"/> at 0, so the port condition was false and the branch was
/// never taken.
/// </para>
/// <para>
/// The primary guard is therefore <see cref="HttpContext.GetEndpoint"/> rather than the prefix list:
/// routing runs at the start of the pipeline (no explicit <c>UseRouting</c> call, so the host inserts
/// it there), which means every mapped API route already has an endpoint selected by the time this
/// predicate runs. A new controller or minimal-API route is excluded automatically and cannot regress
/// this way again. The prefix checks are kept as a second line of defence for paths that are
/// API-shaped but unmapped — <c>/api/does-not-exist</c> should 404 as an API, not render the console.
/// </para>
/// </summary>
public static class AdminSpaRouting
{
    private static readonly string[] NonSpaPrefixes =
        ["/api", "/oauth2", "/.well-known", "/health", "/metrics"];

    public static bool ShouldServeSpa(HttpContext context, int httpPort)
    {
        if (context.Connection.LocalPort != httpPort)
        {
            return false;
        }

        // A matched endpoint means some Map* call owns this request; the SPA must not swallow it.
        if (context.GetEndpoint() != null)
        {
            return false;
        }

        var path = context.Request.Path;
        return !NonSpaPrefixes.Any(prefix => path.StartsWithSegments(prefix));
    }
}
