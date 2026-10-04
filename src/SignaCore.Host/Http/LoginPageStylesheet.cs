namespace SignaCore.Host.Http;

/// <summary>
/// The one same-origin stylesheet of the hosted login page, served at
/// <see cref="Path"/> and admitted by the page's <c>style-src 'self'</c>. It is a Host constant
/// rather than a <c>wwwroot</c> file: <c>wwwroot</c> belongs to the administration console build,
/// and its fallback does not serve every port. The sheet loads nothing else — no font, image,
/// <c>url()</c>, or <c>@import</c> — and uses fixed presentation classes without changing the form field contract.
/// </summary>
internal static class LoginPageStylesheet
{
    public const string Path = "/oauth2/login/style.css";

    public const string ContentType = "text/css; charset=utf-8";

    public const string CacheControl = "public, max-age=3600";

    public const string Content =
        """
        :root{color-scheme:light dark;--page:#f4f5fb;--surface:#fff;--text:#202638;--muted:#535f76;--primary:#4338ca;--primary-hover:#3730a3;--primary-active:#312e81;--border:#7c8497;--divider:#dce0eb;--focus:#4338ca;--error:#9f1239;--error-bg:#fff1f2;--info:#344c80;--info-bg:#edf2ff;--soft:#f1f3fb;--space-1:8px;--space-2:12px;--space-3:16px;--space-4:24px;--space-5:32px}
        *,*::before,*::after{box-sizing:border-box}
        html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
        body{margin:0;min-height:100vh;padding:64px var(--space-3);background:radial-gradient(ellipse at top,#e7e9fc 0,transparent 65%),var(--page);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif}
        main{width:100%;max-width:440px;margin:0 auto;padding:var(--space-5);background:var(--surface);border:1px solid var(--divider);border-radius:20px;box-shadow:0 16px 48px #20263812;overflow-wrap:anywhere}
        .page-header{margin-bottom:var(--space-4)}
        .wordmark{margin:0 0 var(--space-4);color:var(--primary);font-size:18px;line-height:1.5;font-weight:750;letter-spacing:-.4px}
        h1{margin:0 0 var(--space-1);font-size:28px;line-height:1.25;font-weight:700;letter-spacing:-.5px}
        .description{margin:0;color:var(--muted)}
        h2{margin:0 0 var(--space-3);font-size:18px;line-height:1.5;font-weight:650}
        p{margin:0 0 var(--space-3)}
        form{margin:0}
        label{display:block;margin-bottom:var(--space-1);font-size:14px;line-height:1.5;font-weight:600}
        input{display:block;width:100%;min-width:0;min-height:48px;padding:10px var(--space-2);font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:10px}
        input:hover{border-color:var(--focus)}
        button{min-height:44px;padding:10px var(--space-3);font:inherit;line-height:1.5;font-weight:600;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:10px;cursor:pointer;overflow-wrap:normal}
        button:hover{background:var(--soft)}
        button:active{background:var(--divider)}
        button[value="login"],button[value="sms_login"]{display:block;width:100%;min-height:48px;color:#fff;background:var(--primary);border-color:var(--primary)}
        button[value="login"]:hover,button[value="sms_login"]:hover{background:var(--primary-hover);border-color:var(--primary-hover)}
        button[value="login"]:active,button[value="sms_login"]:active{background:var(--primary-active);border-color:var(--primary-active)}
        button[value="cancel"]{display:block;width:100%;margin-top:var(--space-1);color:var(--muted);background:transparent;border-color:transparent}
        button[value="cancel"]:hover,button[value="cancel"]:active{color:var(--text);background:var(--soft)}
        input:focus-visible,button:focus-visible{outline:3px solid var(--focus);outline-offset:3px}
        .actions{margin-bottom:0}
        .sms-region{margin-top:var(--space-4);padding-top:var(--space-4);border-top:1px solid var(--divider)}
        .otp-row{display:flex;flex-wrap:wrap;align-items:flex-end;gap:var(--space-2);margin-bottom:var(--space-3)}
        .otp-field{flex:1 1 130px;min-width:0;margin:0}
        .otp-row button{flex:0 1 auto;max-width:100%;overflow-wrap:anywhere;min-height:48px;padding-inline:var(--space-2)}
        .notice{margin:0 0 var(--space-3);padding:var(--space-2) var(--space-3);border:1px solid currentColor;border-radius:10px;font-size:14px;line-height:1.5}
        [role="alert"]{color:var(--error);background:var(--error-bg)}
        [role="status"]{color:var(--info);background:var(--info-bg)}
        .error-message{margin:0;color:var(--muted)}
        @media (max-width:480px){body{padding:var(--space-4) var(--space-3)}main{padding:var(--space-4)}h1{font-size:26px}}
        @media (prefers-color-scheme:dark){:root{--page:#101423;--surface:#191e30;--text:#f2f3fb;--muted:#b3bed5;--primary:#b3abff;--primary-hover:#c9c3ff;--primary-active:#a39aef;--border:#8792ab;--divider:#374057;--focus:#c4b5fd;--error:#ffb4c8;--error-bg:#361d2d;--info:#bdd0ff;--info-bg:#1e2b47;--soft:#293148}body{background:radial-gradient(ellipse at top,#25264e 0,transparent 65%),var(--page)}main{box-shadow:0 16px 48px #0003}button[value="login"],button[value="sms_login"]{color:#17132e}}


        """;
}
