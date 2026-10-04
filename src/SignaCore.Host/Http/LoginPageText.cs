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
    string Description,
    string UsernameLabel,
    string PasswordLabel,
    string SignInButton,
    string CancelButton,
    string CredentialFailureNotice,
    string SmsCodeSentNotice,
    string InvalidPhoneNotice,
    string SmsFailureNotice,
    string SmsHeading,
    string PhoneLabel,
    string OtpLabel,
    string SendCodeButton,
    string SmsSignInButton,
    string ErrorTitle,
    string ErrorHeading,
    string ErrorMessage)
{
    public static readonly LoginPageText English = new(
        HtmlLang: "en",
        PageTitle: "Sign in",
        Heading: "Sign in",
        Description: "Continue to your application.",
        UsernameLabel: "Username",
        PasswordLabel: "Password",
        SignInButton: "Sign in",
        CancelButton: "Cancel",
        CredentialFailureNotice: "Sign-in failed. Check your username and password and try again.",
        SmsCodeSentNotice: "If this phone number can sign in to this application, a verification "
            + "code has been sent.",
        InvalidPhoneNotice: "Enter a valid mainland China mobile number.",
        SmsFailureNotice: "Sign-in failed. Check your mobile number and verification code and try "
            + "again, or request a new code.",
        SmsHeading: "Sign in with a verification code",
        PhoneLabel: "Mobile number",
        OtpLabel: "Verification code",
        SendCodeButton: "Send code",
        SmsSignInButton: "Sign in with code",
        ErrorTitle: "Invalid login request",
        ErrorHeading: "Invalid login request",
        ErrorMessage: "The login request could not be processed. Return to the application that "
            + "sent you here and start again.");

    public static readonly LoginPageText SimplifiedChinese = new(
        HtmlLang: "zh-CN",
        PageTitle: "登录",
        Heading: "登录",
        Description: "登录后继续使用应用。",
        UsernameLabel: "用户名",
        PasswordLabel: "密码",
        SignInButton: "登录",
        CancelButton: "取消",
        CredentialFailureNotice: "登录失败。请检查用户名和密码后重试。",
        SmsCodeSentNotice: "如果此手机号可以登录该应用，验证码已发送。",
        InvalidPhoneNotice: "请输入有效的中国大陆手机号码。",
        SmsFailureNotice: "登录失败。请检查手机号和验证码后重试，或重新获取验证码。",
        SmsHeading: "使用短信验证码登录",
        PhoneLabel: "手机号",
        OtpLabel: "验证码",
        SendCodeButton: "发送验证码",
        SmsSignInButton: "验证码登录",
        ErrorTitle: "登录请求无效",
        ErrorHeading: "登录请求无效",
        ErrorMessage: "无法处理此登录请求。请返回将您引导至此处的应用，然后重新开始。");

    public static LoginPageText For(LoginPageLanguage language) => language switch
    {
        LoginPageLanguage.SimplifiedChinese => SimplifiedChinese,
        _ => English
    };
}
