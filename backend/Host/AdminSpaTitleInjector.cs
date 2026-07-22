namespace QuantumZhou.Identity.Host;

/// <summary>
/// Injects the runtime APP_TITLE value into the admin SPA index.html:
/// replaces the __APP_TITLE__ placeholder (browser tab title) and injects a
/// window.__APP_TITLE__ script tag for the Vue app to read at runtime.
/// </summary>
public static class AdminSpaTitleInjector
{
    public static string Inject(string html, string appTitle)
    {
        var content = html.Replace("__APP_TITLE__", appTitle);
        var escapedTitle = appTitle.Replace("'", "\\'");
        return content.Replace("</head>", $"<script>window.__APP_TITLE__ = '{escapedTitle}';</script></head>");
    }
}
