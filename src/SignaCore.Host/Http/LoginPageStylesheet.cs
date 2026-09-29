namespace SignaCore.Host.Http;

/// <summary>
/// The one same-origin stylesheet of the hosted login page, served at
/// <see cref="Path"/> and admitted by the page's <c>style-src 'self'</c>. It is a Host constant
/// rather than a <c>wwwroot</c> file: <c>wwwroot</c> belongs to the administration console build,
/// and its fallback does not serve every port. The sheet loads nothing else — no font, image,
/// <c>url()</c>, or <c>@import</c> — and styles only element and attribute selectors, so the page
/// markup and its field contract stay unchanged.
/// </summary>
internal static class LoginPageStylesheet
{
    public const string Path = "/oauth2/login/style.css";

    public const string ContentType = "text/css; charset=utf-8";

    public const string CacheControl = "public, max-age=3600";

    public const string Content =
        """
        *,*::before,*::after{box-sizing:border-box}
        html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
        body{margin:0;min-height:100vh;padding:48px 16px;background:#f3f4f6;color:#1f2328;font:16px/1.5 system-ui,-apple-system,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif}
        main{width:100%;max-width:400px;margin:0 auto;padding:32px 24px;background:#fff;border:1px solid #d8dee4;border-radius:12px}
        h1{margin:0 0 24px;font-size:24px;line-height:1.25;font-weight:600}
        h2{margin:24px 0 16px;padding-top:24px;border-top:1px solid #d8dee4;font-size:18px;line-height:1.25;font-weight:600}
        p{margin:0 0 16px}
        label{display:block;margin-bottom:6px;font-weight:500}
        input{display:block;width:100%;padding:10px 12px;font:inherit;color:inherit;background:#fff;border:1px solid #c9d1d9;border-radius:8px}
        button{min-width:96px;margin:8px 8px 0 0;padding:10px 16px;font:inherit;color:#1f2328;background:#f6f8fa;border:1px solid #c9d1d9;border-radius:8px;cursor:pointer}
        button[value="login"],button[value="sms_login"]{color:#fff;background:#0969da;border-color:#0969da}
        input:focus-visible,button:focus-visible{outline:2px solid #0969da;outline-offset:2px}
        [role="alert"]{padding:10px 12px;color:#82071e;background:#ffebe9;border:1px solid #ffb3b8;border-radius:8px}
        @media (max-width:480px){body{padding:24px 16px}main{padding:24px 16px}button{width:100%;margin-right:0}}
        @media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}main{background:#161b22;border-color:#30363d}h2{border-top-color:#30363d}input{background:#0d1117;border-color:#30363d}button{color:#e6edf3;background:#21262d;border-color:#30363d}button[value="login"],button[value="sms_login"]{color:#fff;background:#1f6feb;border-color:#1f6feb}[role="alert"]{color:#ffdcd7;background:#3d1418;border-color:#8e1519}}

        """;
}
