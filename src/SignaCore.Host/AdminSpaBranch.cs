using Microsoft.AspNetCore.StaticFiles;

namespace SignaCore.Host;

/// <summary>
/// Serves the administrative SPA. Shared by the setup-mode host and the normal host so the setup
/// page and the console are the same build, served the same way.
/// </summary>
internal static class AdminSpaBranch
{
    public static void Map(WebApplication app, int httpPort)
    {
        var appTitle = app.Configuration["APP_TITLE"] ?? "SignaCore";

        app.MapWhen(context => AdminSpaRouting.ShouldServeSpa(context, httpPort),
            adminApp =>
            {
                adminApp.UseDefaultFiles();

                // Inject app title from APP_TITLE env var into index.html at runtime
                adminApp.Use(async (context, next) =>
                {
                    if (context.Request.Path == "/index.html")
                    {
                        var wwwroot = app.Environment.WebRootPath;
                        var filePath = Path.Combine(wwwroot ?? string.Empty, "index.html");
                        if (File.Exists(filePath))
                        {
                            var content = await File.ReadAllTextAsync(filePath, context.RequestAborted);
                            content = AdminSpaTitleInjector.Inject(content, appTitle);
                            context.Response.ContentType = "text/html; charset=utf-8";
                            await context.Response.WriteAsync(content, context.RequestAborted);
                            return;
                        }
                    }

                    await next();
                });

                adminApp.UseStaticFiles();

                // SPA fallback for Vue Router history mode
                adminApp.MapWhen(_ => true, spaApp =>
                {
                    spaApp.Use(async (context, next) =>
                    {
                        context.Request.Path = "/index.html";
                        await next();
                    });
                    spaApp.UseStaticFiles();
                });
            });
    }

    /// <summary>
    /// Serves the admin SPA on the normal host through a mapped fallback endpoint rather than a
    /// post-pipeline branch, and returns the endpoint's builder.
    /// </summary>
    /// <remarks>
    /// The normal host composes the ServiceMantle pipeline, which owns routing and runs a phase
    /// gate that answers 404 for any request left without an endpoint. A <c>MapWhen</c> branch
    /// placed after that pipeline therefore never runs, and one placed before it is not routed yet,
    /// so the endpoint guard in <see cref="AdminSpaRouting.ShouldServeSpa"/> cannot protect the API
    /// routes. Mapping the SPA as the lowest-priority catch-all endpoint instead lets an unmatched
    /// GET/HEAD navigation reach the console while routing, the phase gate, and every mapped API
    /// endpoint keep precedence, and the <c>/setup</c> and <c>/bootstrap</c> redirect middleware —
    /// which runs after the gate but before endpoints — stays effective. The endpoint serves files
    /// itself: the static-file middleware does not serve a request whose selected endpoint already
    /// carries a request delegate. The method is limited to GET and HEAD so an unmatched POST keeps
    /// routing's 405 rather than being turned into a 404 or an HTML body. The returned builder lets
    /// the Bootstrap Configuration Mode host mark the same fallback with its own phase admission;
    /// the normal host ignores it.
    /// </remarks>
    public static IEndpointConventionBuilder MapNormalHostSpaFallback(WebApplication app, int httpPort)
    {
        var appTitle = app.Configuration["APP_TITLE"] ?? "SignaCore";
        var contentTypeProvider = new FileExtensionContentTypeProvider();

        return app.MapFallback("{**path}", async (HttpContext context) =>
            {
                if (!AdminSpaRouting.ShouldServeSpaFallback(context, httpPort))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                var webRoot = app.Environment.WebRootPath;
                var relativePath = context.Request.Path.Value?.TrimStart('/') ?? string.Empty;

                // `/` and `/index.html` receive the runtime title injection.
                if (relativePath.Length == 0 ||
                    string.Equals(relativePath, "index.html", StringComparison.OrdinalIgnoreCase))
                {
                    await ServeInjectedIndexAsync(context, webRoot, appTitle);
                    return;
                }

                // A concrete file in the web root (assets, favicons, …) is served verbatim.
                if (TryResolveWebRootFile(webRoot, relativePath, contentTypeProvider,
                        out var filePath, out var contentType))
                {
                    context.Response.ContentType = contentType;
                    await context.Response.SendFileAsync(filePath, context.RequestAborted);
                    return;
                }

                // History fallback: every other unmatched SPA route returns the raw index.html.
                await ServeRawIndexAsync(context, webRoot);
            })
            .WithMetadata(new HttpMethodMetadata(["GET", "HEAD"]));
    }

    private static async Task ServeInjectedIndexAsync(HttpContext context, string? webRoot, string appTitle)
    {
        var indexPath = IndexFilePath(webRoot);
        if (indexPath is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var content = await File.ReadAllTextAsync(indexPath, context.RequestAborted);
        content = AdminSpaTitleInjector.Inject(content, appTitle);
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(content, context.RequestAborted);
    }

    private static async Task ServeRawIndexAsync(HttpContext context, string? webRoot)
    {
        var indexPath = IndexFilePath(webRoot);
        if (indexPath is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        // The history fallback mirrors the branch host: the raw index.html, without title injection.
        context.Response.ContentType = "text/html";
        await context.Response.SendFileAsync(indexPath, context.RequestAborted);
    }

    /// <summary>
    /// Resolves <c>index.html</c> under the web root, or <c>null</c> when there is no web root or no
    /// index to serve; a missing index is answered 404 rather than as an empty console.
    /// </summary>
    private static string? IndexFilePath(string? webRoot)
    {
        if (string.IsNullOrEmpty(webRoot))
        {
            return null;
        }

        var indexPath = Path.Combine(webRoot, "index.html");
        return File.Exists(indexPath) ? indexPath : null;
    }

    /// <summary>
    /// Resolves a concrete file inside the web root, rejecting any path that escapes it. The content
    /// type comes from the file extension, defaulting to an opaque binary type.
    /// </summary>
    private static bool TryResolveWebRootFile(
        string? webRoot,
        string relativePath,
        FileExtensionContentTypeProvider contentTypeProvider,
        out string filePath,
        out string contentType)
    {
        filePath = string.Empty;
        contentType = "application/octet-stream";
        if (string.IsNullOrEmpty(webRoot))
        {
            return false;
        }

        var root = Path.GetFullPath(webRoot);
        string candidate;
        try
        {
            candidate = Path.GetFullPath(Path.Combine(root, relativePath));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }

        // Path traversal must not escape the web root.
        if (!candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            !File.Exists(candidate))
        {
            return false;
        }

        if (contentTypeProvider.TryGetContentType(candidate, out var resolved))
        {
            contentType = resolved;
        }

        filePath = candidate;
        return true;
    }
}
