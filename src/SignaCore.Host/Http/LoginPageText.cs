namespace SignaCore.Host.Http;

/// <summary>
/// The rendered text of the hosted login page in one language. Every language instance sets every
/// member (the record has no optional member), so a language cannot ship with a missing string.
/// The values are fixed literals: none is derived from a request, a stored continuation, or
/// configuration, and none contains markup-significant characters, so they are written into the
/// page as they are. API, log, audit, and exception text stays English and never uses this type.
/// </summary>
internal sealed record LoginPageText(
    string HtmlLang,
    string PageTitle,
    string Heading,
    string UsernameLabel,
    string PasswordLabel,
    string SignInButton,
    string CancelButton,
    string CredentialFailureNotice,
    string ErrorTitle,
    string ErrorHeading,
    string ErrorMessage)
{
    public static readonly LoginPageText English = new(
        HtmlLang: "en",
        PageTitle: "Sign in",
        Heading: "Sign in",
        UsernameLabel: "Username",
        PasswordLabel: "Password",
        SignInButton: "Sign in",
        CancelButton: "Cancel",
        CredentialFailureNotice: "Sign-in failed. Check your username and password and try again.",
        ErrorTitle: "Invalid login request",
        ErrorHeading: "Invalid login request",
        ErrorMessage: "The login request could not be processed. Return to the application that "
            + "sent you here and start again.");

    public static readonly LoginPageText SimplifiedChinese = new(
        HtmlLang: "zh-CN",
        PageTitle: "登录",
        Heading: "登录",
        UsernameLabel: "用户名",
        PasswordLabel: "密码",
        SignInButton: "登录",
        CancelButton: "取消",
        CredentialFailureNotice: "登录失败。请检查用户名和密码后重试。",
        ErrorTitle: "登录请求无效",
        ErrorHeading: "登录请求无效",
        ErrorMessage: "无法处理此登录请求。请返回将您引导至此处的应用，然后重新开始。");

    public static LoginPageText For(LoginPageLanguage language) => language switch
    {
        LoginPageLanguage.SimplifiedChinese => SimplifiedChinese,
        _ => English
    };
}
