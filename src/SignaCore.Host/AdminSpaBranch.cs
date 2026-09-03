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
}
