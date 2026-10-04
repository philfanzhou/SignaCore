using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;
using Microsoft.AspNetCore.RateLimiting;

namespace SignaCore.Host.Controllers;

/// <summary>
/// The browser-side identity login of the interactive Authorization Code flow:
/// <c>GET /oauth2/login</c> renders the form for an active continuation (<c>IN-10</c>),
/// <c>POST /oauth2/login</c> processes the Password login, SMS login, or cancel submission
/// (<c>IN-11</c>–<c>IN-15</c>, <c>IN-17</c>–<c>IN-19</c>), and <c>POST /oauth2/login/sms-code</c> is
/// the browser SMS send route (<c>IN-16</c>, <c>IN-17</c>, <c>IN-19</c>, <c>EV-35</c>). While the
/// <c>IN-19</c> gate of the continuation's application is open, every rendered login page carries
/// the SMS region as a second form (<c>AC-17</c>).
/// </summary>
/// <remarks>
/// This controller delivers the browser surface, the antiforgery chain (<c>PS-19</c>), the local
/// result of a credential failure (<c>EV-17</c>), the cancel exit (<c>EV-02</c>), and the success
/// exit (<c>EV-01</c>): revalidating the current client, the exact redirect URI, and the scope
/// against the stored snapshot, then — for a passing credential check — committing the
/// continuation consumption, the new identity session, the new authorization code, the
/// failure-counter clear, the login-info update, and the success audit as one transaction
/// (<see cref="OidcLoginCompletionService"/>) before the fresh <c>PS-18</c> identity cookie and the
/// <c>PS-17</c> success redirect are written. The SMS login follows the same shape with its own
/// generic failure (<c>EV-37</c>, <see cref="OidcSmsLoginFailureRecorder"/>) and success
/// transaction (<c>EV-36</c>, <see cref="OidcSmsLoginCompletionService"/>). The cancel exit consumes the continuation and
/// returns the <c>access_denied</c> safe redirect. A missing, malformed, unknown, expired, or
/// consumed handle shares the single local 400 of <c>EV-03</c>/<c>SC-18</c>: no redirect, no
/// credential check, no failure count, no replay audit.
/// <para>
/// The controller is deliberately not an <c>[ApiController]</c> and binds no parameters: the form
/// is parsed by hand under a strict structure contract, because the automatic model-binding 400
/// would answer with JSON ProblemDetails and violate the local HTML result contract. Every
/// rejection returns one identical local page per negotiated language that echoes no request
/// value, and every response carries the fixed browser security headers and denies framing. The
/// page language comes from <c>Accept-Language</c> only (<see cref="LoginPageLanguageNegotiator"/>);
/// field names, order, and error routing are the same in every language. A <c>Location</c> appears only
/// on the two verified exits — the cancel's <c>access_denied</c> redirect and the success's
/// <c>code</c> redirect — both to the exact registered URI. The page renders no stored
/// continuation value — no redirect URI, scope, state, nonce, or challenge — so the login surface
/// cannot be used to read them back. The only stored-derived value on a rendered form is the
/// callback origin in its <c>form-action</c> directive, which the browser learns from the redirect
/// anyway.
/// </para>
/// </remarks>
[Route("oauth2/login")]
public sealed partial class OAuthLoginController : ControllerBase
{
    /// <summary>
    /// The single local 400 body of each page language. Every structural, handle, action,
    /// antiforgery, and credential-field failure returns exactly these bytes for the negotiated
    /// language and echoes no request value (<c>SC-19</c>: an invalid CSRF answer is
    /// indistinguishable from any other local rejection).
    /// </summary>
    private static readonly string EnglishLocalErrorPage = BuildLocalErrorPage(LoginPageText.English);

    private static readonly string SimplifiedChineseLocalErrorPage =
        BuildLocalErrorPage(LoginPageText.SimplifiedChinese);

    private const string HtmlContentType = "text/html; charset=utf-8";

    /// <summary>
    /// The fixed Content-Security-Policy of every <c>/oauth2/login</c> response that is not a
    /// rendered form: the local 400 and the cancel and success redirects. <c>style-src 'self'</c>
    /// admits only the page's own stylesheet; the page loads no script.
    /// </summary>
    private const string DefaultContentSecurityPolicy =
        "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

    /// <summary>
    /// The shared head of every rendered HTML page after its <c>&lt;title&gt;</c>: the mobile
    /// viewport and the one same-origin stylesheet.
    /// </summary>
    private const string HeadTail =
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        + "<link rel=\"stylesheet\" href=\"" + LoginPageStylesheet.Path + "\">";

    /// <summary>The canonical 16 KiB bound of the POST form body.</summary>
    private const int MaxRequestBodyBytes = 16 * 1024;

    /// <summary>The <c>IN-13</c> bound of the submitted password in UTF-16 code units.</summary>
    private const int MaxPasswordLength = 1024;

    private const string FormFieldNameLoginHandle = "login_handle";
    private const string FormFieldNameUsername = "username";
    private const string FormFieldNamePassword = "password";
    private const string FormFieldNameAction = "action";
    private const string LoginActionValue = "login";
    private const string CancelActionValue = "cancel";
    private const string SmsLoginActionValue = "sms_login";
    private const string FormFieldNamePhone = "phone";
    private const string FormFieldNameOtp = "otp";

    private const string FormUrlEncodedContentType = "application/x-www-form-urlencoded";
    private const string CharsetParameterName = "charset";
    private const string Utf8Charset = "utf-8";

    // The closed reason and outcome names written to the logs. They are aggregates only; no
    // handle, credential, or antiforgery value ever reaches a log message (DF-01/DF-05, PS-19).
    private const string ReasonQueryStructure = "query_structure";
    private const string ReasonBodyStructure = "body_structure";
    private const string ReasonContinuationUnavailable = "continuation_unavailable";
    private const string ReasonAction = "action";
    private const string ReasonAntiforgery = "antiforgery";
    private const string ReasonCredentialField = "credential_field";
    private const string ReasonClientUnavailable = "client_unavailable";
    private const string ReasonSmsCapability = "sms_capability";
    private const string ReasonPhoneField = "phone_field";
    private const string ReasonOtpField = "otp_field";
    private const string OutcomeCancelRedirected = "cancel_redirected";
    private const string OutcomeCancelRejected = "cancel_rejected";
    private const string OutcomeCredentialFailure = "credential_failure";
    private const string OutcomeLoginCompleted = "login_completed";
    private const string OutcomeLoginRedirectRejected = "login_redirect_rejected";
    private const string OutcomeLoginClientRejected = "login_client_rejected";
    private const string OutcomeSmsLoginCompleted = "sms_login_completed";
    private const string OutcomeSmsLoginRedirectRejected = "sms_login_redirect_rejected";
    private const string OutcomeSmsLoginClientRejected = "sms_login_client_rejected";

    // The closed login-sms metric outcomes (canonical "Audit and metrics").
    private const string SmsLoginMetricSuccess = "success";
    private const string SmsLoginMetricFailure = "failure";
    private const string SmsLoginMetricLocalRejected = "local_rejected";

    /// <summary>
    /// The seven admitted POST form fields (<c>IN-11</c>–<c>IN-15</c>, <c>IN-17</c>, <c>IN-18</c>),
    /// matched ordinally. The Password form posts the first five and the SMS form posts the handle,
    /// the request token, the action, <c>phone</c>, and <c>otp</c>; each action ignores the other
    /// form's fields without validating them.
    /// </summary>
    private static readonly string[] AdmittedFormFields =
    [
        FormFieldNameLoginHandle,
        FormFieldNameUsername,
        FormFieldNamePassword,
        LoginAntiforgeryDefaults.TokenFieldName,
        FormFieldNameAction,
        FormFieldNamePhone,
        FormFieldNameOtp,
    ];

    /// <summary>
    /// The four admitted fields of the SMS send route (<c>IN-16</c>), matched ordinally. The
    /// <c>otp</c> field is admitted because the SMS form's send button posts every field of that
    /// form except the unnamed button itself, and it is ignored without validation.
    /// </summary>
    private static readonly string[] AdmittedSmsCodeFormFields =
    [
        FormFieldNameLoginHandle,
        LoginAntiforgeryDefaults.TokenFieldName,
        FormFieldNamePhone,
        FormFieldNameOtp,
    ];

    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly IAuthorizationRequestStore _continuations;
    private readonly ILoginAntiforgeryService _antiforgery;
    private readonly ValidatorFactory _validatorFactory;
    private readonly IOidcAuthorizationRequestValidator _revalidator;
    private readonly OidcLoginFailureRecorder _failureRecorder;
    private readonly OidcLoginCompletionService _loginCompletion;
    private readonly OidcSmsCodeSendService _smsCodeSend;
    private readonly OidcSmsLoginFailureRecorder _smsFailureRecorder;
    private readonly OidcSmsLoginCompletionService _smsLoginCompletion;
    private readonly ISmsAdmissionService _smsAdmissions;
    private readonly IOtpService _otpService;
    private readonly IdentityDbContext _dbContext;
    private readonly JwtOptions _jwtOptions;
    private readonly AuthMetrics _metrics;
    private readonly ILogger<OAuthLoginController> _logger;

    public OAuthLoginController(
        IAuthorizationRequestStore continuations,
        ILoginAntiforgeryService antiforgery,
        ValidatorFactory validatorFactory,
        IOidcAuthorizationRequestValidator revalidator,
        OidcLoginFailureRecorder failureRecorder,
        OidcLoginCompletionService loginCompletion,
        OidcSmsCodeSendService smsCodeSend,
        OidcSmsLoginFailureRecorder smsFailureRecorder,
        OidcSmsLoginCompletionService smsLoginCompletion,
        ISmsAdmissionService smsAdmissions,
        IOtpService otpService,
        IdentityDbContext dbContext,
        JwtOptions jwtOptions,
        AuthMetrics metrics,
        ILogger<OAuthLoginController> logger)
    {
        _continuations = continuations;
        _antiforgery = antiforgery;
        _validatorFactory = validatorFactory;
        _revalidator = revalidator;
        _failureRecorder = failureRecorder;
        _loginCompletion = loginCompletion;
        _smsCodeSend = smsCodeSend;
        _smsFailureRecorder = smsFailureRecorder;
        _smsLoginCompletion = smsLoginCompletion;
        _smsAdmissions = smsAdmissions;
        _otpService = otpService;
        _dbContext = dbContext;
        _jwtOptions = jwtOptions;
        _metrics = metrics;
        _logger = logger;
    }

    /// <summary>
    /// Serves the login page stylesheet. The response is the same fixed constant for every request:
    /// the action reads no query, body, cookie, or header, needs no identity or management
    /// authentication, writes no cookie, and has no OIDC rate-limit policy (the host-wide limit
    /// still applies). It declares no parameters so MVC never binds anything on this route.
    /// </summary>
    [HttpGet("style.css")]
    public IActionResult GetStylesheet()
    {
        Response.Headers.CacheControl = LoginPageStylesheet.CacheControl;
        Response.Headers.XContentTypeOptions = "nosniff";
        return Content(LoginPageStylesheet.Content, LoginPageStylesheet.ContentType);
    }

    /// <summary>
    /// Renders the login form for an active continuation. The query must carry exactly one
    /// <c>login_handle</c> and nothing else; every other shape shares the local 400 with a
    /// missing, malformed, unknown, expired, or consumed handle (<c>IN-10</c>, <c>EV-03</c>).
    /// The antiforgery cookie is written only when the browser does not already present a usable
    /// one, so parallel tabs keep validating against the same secret (<c>PS-19</c>). The action
    /// declares no parameters for the same reason as the POST below: MVC's value providers must
    /// never touch this route's request body.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ShowLoginForm()
    {
        ApplyBrowserSecurityHeaders();
        var cancellationToken = HttpContext.RequestAborted;

        var query = Request.Query;
        if (query.Count != 1
            || !query.TryGetValue(FormFieldNameLoginHandle, out var handleValues)
            || handleValues.Count != 1)
        {
            return RejectLocally(ReasonQueryStructure);
        }

        var loginHandle = handleValues[0]!;

        // PS-22: one captured UTC instant per request for the continuation lookup.
        var now = DateTimeOffset.UtcNow;
        var continuation = await _continuations.GetActiveAsync(loginHandle, now, cancellationToken);
        if (continuation is null)
        {
            return RejectLocally(ReasonContinuationUnavailable);
        }

        var pair = _antiforgery.IssuePair(Request.Cookies[LoginAntiforgeryDefaults.CookieName]);
        if (!pair.ReusedExistingCookie)
        {
            Response.Cookies.Append(
                LoginAntiforgeryDefaults.CookieName,
                pair.CookieValue,
                CreateAntiforgeryCookieOptions());
        }

        // IN-19 is read from the current application row at every render. A missing row cannot
        // come from a consistent database (PS-23); it renders the Password form alone.
        var capability = await _dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.Id == continuation.AppRegistrationId)
            .Select(app => new { app.SmsLoginMode, app.SmsProfileKey })
            .FirstOrDefaultAsync(cancellationToken);
        var smsRegion = capability is not null && IsSmsCapabilityOpen(capability.SmsLoginMode, capability.SmsProfileKey)
            ? SmsRegion.Empty
            : (SmsRegion?)null;

        ApplyLoginFormContentSecurityPolicy(continuation);
        return HtmlPage(
            BuildLoginPage(NegotiatedText(), loginHandle, pair.RequestToken, notice: null, smsRegion),
            StatusCodes.Status200OK);
    }

    /// <summary>
    /// Processes the login form submission in the single canonical order: structure, continuation,
    /// action, antiforgery, the cancel exit, the conditional credential fields, and only then the
    /// shared Password validator. A cancel submission revalidates the current client and the exact
    /// redirect URI, consumes the continuation, and redirects <c>access_denied</c> (<c>EV-02</c>)
    /// before username and password are read at all (<c>IN-15</c>); a credential failure commits
    /// its counter and audit unit before the identical generic page is rendered
    /// (<c>EV-17</c>); a passing credential check revalidates the current client, the exact
    /// redirect URI, and the scope, commits the <c>EV-01</c> success transaction, and only then
    /// issues the fresh identity cookie and the <c>code</c> redirect.
    /// <para>
    /// The action deliberately declares no parameters — not even a <see cref="CancellationToken"/>
    /// — and reads <see cref="HttpContext.RequestAborted"/> itself. With any declared parameter,
    /// MVC creates its value providers before the action runs, and the form value provider calls
    /// <c>ReadFormAsync</c> on every form-content-type request: a lenient parse that both drains
    /// the body this action must parse strictly and can throw the framework's own 400 outside the
    /// local error contract. Zero parameters keeps MVC's binding machinery — and its body read —
    /// off this route entirely.
    /// </para>
    /// </summary>
    [HttpPost]
    [EnableRateLimiting(OidcRateLimitPolicies.Login)]
    public async Task<IActionResult> SubmitLoginForm()
    {
        var stopwatch = Stopwatch.StartNew();
        ApplyBrowserSecurityHeaders();
        var cancellationToken = HttpContext.RequestAborted;

        // ① Structure: no query string, the exact form content type, the bounded body, and the
        // strict parse with per-field cardinality and the closed field set.
        if (Request.QueryString.HasValue && Request.QueryString.Value!.Length > 0)
        {
            return RejectLocally(ReasonQueryStructure);
        }

        if (!IsAdmittedContentType(Request.ContentType))
        {
            return RejectLocally(ReasonBodyStructure);
        }

        // The size bound is enforced on the bytes actually read, never on the client-declared
        // Content-Length header: ReadBoundedBodyAsync stops at one byte past the limit, and the
        // length check below rejects on the real byte count. A lying or absent Content-Length
        // therefore cannot smuggle an oversized body past the bound.
        var body = await ReadBoundedBodyAsync(MaxRequestBodyBytes + 1, cancellationToken);
        if (body.Length > MaxRequestBodyBytes
            || !TryParseStrictForm(body, AdmittedFormFields, out var fields))
        {
            return RejectLocally(ReasonBodyStructure);
        }

        // ② Continuation (IN-11, EV-03): the store owns the shape check and the constant-time
        // digest comparison and answers every unusable handle with the same null.
        if (!fields.TryGetValue(FormFieldNameLoginHandle, out var loginHandle))
        {
            return RejectLocally(ReasonContinuationUnavailable);
        }

        var now = DateTimeOffset.UtcNow;
        var continuation = await _continuations.GetActiveAsync(loginHandle, now, cancellationToken);
        if (continuation is null)
        {
            return RejectLocally(ReasonContinuationUnavailable);
        }

        // ③ Action (IN-15): ordinal membership in the closed set; no case folding.
        if (!fields.TryGetValue(FormFieldNameAction, out var action)
            || action is not (LoginActionValue or CancelActionValue or SmsLoginActionValue))
        {
            return RejectLocally(ReasonAction);
        }

        // The SMS login owns its branch from here on; only it records the login-sms metric, and
        // only once its action was read.
        if (action == SmsLoginActionValue)
        {
            var (smsResult, smsOutcome) = await ProcessSmsLoginAsync(
                fields, loginHandle, continuation, now, cancellationToken);
            _metrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.LoginSms, smsOutcome);
            _metrics.RecordOidcEndpointDuration(
                AuthMetrics.OidcMetricEndpoints.LoginSms,
                stopwatch.Elapsed.TotalMilliseconds);
            return smsResult;
        }

        // ④ Antiforgery (IN-14, PS-19): principal-independent pair validation. A failure here
        // never reaches the Password validator and never writes a failure count (SC-19).
        if (!TryValidateAntiforgery(fields, out var requestToken))
        {
            return RejectLocally(ReasonAntiforgery);
        }

        // ⑤ The client snapshot lookup precedes both exits, because the cancel exit needs the
        // client id for its revalidation and the credential exit needs it for the failure audit.
        // The restrictive reference (PS-23) makes a missing row unreachable from a consistent
        // database; the endpoint still fails closed instead of auditing or redirecting a guess.
        var application = await _dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.Id == continuation.AppRegistrationId)
            .Select(app => new { app.AppId, app.SmsLoginMode, app.SmsProfileKey })
            .FirstOrDefaultAsync(cancellationToken);
        if (application is null)
        {
            return RejectLocally(ReasonClientUnavailable);
        }

        var appId = application.AppId;

        // ⑥ Cancel exits before username and password are read (IN-15): revalidate the current
        // client and the exact redirect URI against the stored snapshot, then consume the
        // continuation and redirect access_denied (EV-02). Only the client and the redirect URI
        // are revalidated — a scope removed or refresh disabled since the form was rendered does
        // not block the cancel.
        if (action == CancelActionValue)
        {
            var revalidation = await _revalidator.ValidateAsync(
                OidcContinuationRevalidation.BuildParameters(continuation, appId),
                cancellationToken);
            var redirectUri = revalidation switch
            {
                OidcAuthorizationValidationResult.Accepted accepted => accepted.RegisteredRedirectUri,
                OidcAuthorizationValidationResult.RedirectRejection redirect => redirect.RegisteredRedirectUri,
                _ => null
            };
            var revalidatedApplicationId = revalidation switch
            {
                OidcAuthorizationValidationResult.Accepted accepted => (Guid?)accepted.ApplicationId,
                OidcAuthorizationValidationResult.RedirectRejection redirect => redirect.ApplicationId,
                _ => null
            };
            if (redirectUri is null || revalidatedApplicationId != continuation.AppRegistrationId)
            {
                // Client, capability, or redirect-URI drift is a local error: nothing is consumed
                // and no Location is set. The application-id guard is defense against a client id
                // reassigned to a different application row.
                LogOutcome(OutcomeCancelRejected);
                return RejectLocally(ReasonClientUnavailable);
            }

            if (!await _continuations.TryConsumeAsync(loginHandle, now, cancellationToken))
            {
                // A concurrent consumption or an expiry race answers with the same local page as
                // any unavailable continuation (EV-03).
                LogOutcome(OutcomeCancelRejected);
                return RejectLocally(ReasonContinuationUnavailable);
            }

            LogOutcome(OutcomeCancelRedirected);
            return Redirect(OidcAuthorizationRedirect.BuildError(
                redirectUri,
                OAuthErrorCodes.AccessDenied,
                OidcAuthorizationErrorDescriptions.AccessDenied,
                continuation.State,
                _jwtOptions.Issuer));
        }

        // ⑦ Conditional credential fields (IN-12/IN-13): presence and length bounds around the
        // NFC + invariant-uppercase normalization, no trimming of either value.
        if (!fields.TryGetValue(FormFieldNameUsername, out var username)
            || username.Length == 0
            || username.Length > IdentityConstants.MaxUsernameLength
            || !fields.TryGetValue(FormFieldNamePassword, out var password)
            || password.Length == 0
            || password.Length > MaxPasswordLength)
        {
            return RejectLocally(ReasonCredentialField);
        }

        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        if (normalizedUsername.Length == 0
            || normalizedUsername.Length > IdentityConstants.MaxUsernameLength)
        {
            return RejectLocally(ReasonCredentialField);
        }

        // ⑧ The shared Password validator: one credential chain, one lockout standard, no second
        // password path. The raw username is submitted exactly as the token grants submit it; the
        // repositories own the normalized ordinal lookup.
        var validator = _validatorFactory.GetValidator(IdentityConstants.GrantTypePassword);
        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypePassword,
            Username = username,
            Password = password,
            CancellationToken = cancellationToken
        });

        if (result.IsSuccess)
        {
            // EV-01: the same revalidation entry the cancel exit uses decides the current client,
            // the exact redirect URI, and the current scope against the stored snapshot before
            // anything is consumed. Only its Accepted output — for the same application row —
            // reaches the success transaction.
            var revalidation = await _revalidator.ValidateAsync(
                OidcContinuationRevalidation.BuildParameters(continuation, appId),
                cancellationToken);

            switch (revalidation)
            {
                case OidcAuthorizationValidationResult.Accepted accepted
                    when accepted.ApplicationId == continuation.AppRegistrationId:
                {
                    var completion = await _loginCompletion.CompleteAsync(
                        loginHandle,
                        accepted,
                        result,
                        appId,
                        HttpContext.GetClientIp(),
                        HttpContext.GetUserAgent(),
                        HttpContext.GetCorrelationId(),
                        now,
                        cancellationToken);
                    if (completion is null)
                    {
                        // A concurrent consumption, an expiry race, or an account deactivated
                        // after the credential check shares the single local 400 with any
                        // unavailable continuation (EV-03); the transaction rolled back and
                        // committed nothing.
                        return RejectLocally(ReasonContinuationUnavailable);
                    }

                    // The cookie and the plaintext code are written only after the commit: the
                    // sign-in names the identity scheme explicitly because the default scheme is
                    // the management cookie (PS-18), and the session id is always the fresh one,
                    // never an identity cookie id the request may already carry.
                    await HttpContext.SignInAsync(
                        IdentitySessionDefaults.AuthenticationScheme,
                        IdentitySessionPrincipal.Create(completion.SessionId),
                        new AuthenticationProperties { IsPersistent = false });
                    LogOutcome(OutcomeLoginCompleted);
                    return Redirect(OidcAuthorizationRedirect.BuildSuccess(
                        accepted.RegisteredRedirectUri,
                        completion.Code,
                        continuation.State,
                        _jwtOptions.Issuer));
                }

                case OidcAuthorizationValidationResult.RedirectRejection redirect
                    when redirect.ApplicationId == continuation.AppRegistrationId:
                    // Stage-4 policy drift (a removed scope, refresh disabled while
                    // offline_access was requested) travels to the freshly verified URI with the
                    // canonical error. Nothing is consumed — EV-01 consumes only inside its
                    // success transaction — and no narrowed code is ever issued (SC-04).
                    LogOutcome(OutcomeLoginRedirectRejected);
                    return Redirect(OidcAuthorizationRedirect.BuildError(
                        redirect.RegisteredRedirectUri,
                        redirect.Error,
                        redirect.ErrorDescription,
                        continuation.State,
                        _jwtOptions.Issuer));

                default:
                    // LocalRejection — client deactivated, the interactive capability removed, or
                    // the redirect URI unregistered — or a result resolved to a different
                    // application row: the single local 400 with zero writes, no consumption, no
                    // cookie, and no Location (SC-02/SC-03).
                    LogOutcome(OutcomeLoginClientRejected);
                    return RejectLocally(ReasonClientUnavailable);
            }
        }

        await _failureRecorder.RecordFailureAsync(
            result.LoginAttemptChange,
            username,
            result.ErrorMessage,
            appId,
            HttpContext.GetClientIp(),
            HttpContext.GetUserAgent(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        LogOutcome(OutcomeCredentialFailure);

        // The response is written only after the failure unit has committed. The form reuses the
        // validated handle and request token so the browser can retry against its existing
        // cookie; no cookie is written here and no submitted value is echoed.
        ApplyLoginFormContentSecurityPolicy(continuation);
        var text = NegotiatedText();
        return HtmlPage(
            BuildLoginPage(
                text,
                loginHandle,
                requestToken,
                new LoginNotice(NoticeTarget.Password, AlertRole, text.CredentialFailureNotice),
                IsSmsCapabilityOpen(application.SmsLoginMode, application.SmsProfileKey) ? SmsRegion.Empty : null),
            StatusCodes.Status200OK);
    }

    /// <summary>
    /// The <c>action=sms_login</c> branch after the shared structure, continuation, and action
    /// checks, in the canonical order: antiforgery, the <c>IN-19</c> gate, <c>IN-17</c>,
    /// <c>IN-18</c>, send eligibility, the read-only OTP verification, the <c>EV-01</c> revalidation,
    /// and only then the <c>EV-36</c> transaction. Username and password are ignored without being
    /// read (<c>IN-12</c>/<c>IN-13</c>), and the configured SMS bypass never applies: this path calls
    /// the OTP verifier directly, never the token grant's validator (<c>IN-18</c>).
    /// <para>
    /// Every <c>EV-37</c> case — an ineligible phone, no current sent OTP, a wrong, expired, or
    /// locked code, and a race lost inside <c>EV-36</c> — answers one generic page whose bytes depend
    /// only on the handle, the request token, the normalized phone, and the page language; the true
    /// case reaches only the masked audit row, one closed log reason, and nothing else. Returns the
    /// answer and its closed <c>login-sms</c> metric outcome.
    /// </para>
    /// </summary>
    private async Task<(IActionResult Result, string Outcome)> ProcessSmsLoginAsync(
        IReadOnlyDictionary<string, string> fields,
        string loginHandle,
        AuthorizationRequestEntity continuation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // ④ Antiforgery (IN-14, PS-19): no phone lookup, OTP read, or audit without a valid pair.
        if (!TryValidateAntiforgery(fields, out var requestToken))
        {
            return (RejectLocally(ReasonAntiforgery), SmsLoginMetricLocalRejected);
        }

        // ⑤ The IN-19 gate from the current application row.
        var application = await _dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.Id == continuation.AppRegistrationId)
            .Select(app => new { app.AppId, app.SmsLoginMode, app.SmsProfileKey })
            .FirstOrDefaultAsync(cancellationToken);
        if (application is null)
        {
            return (RejectLocally(ReasonClientUnavailable), SmsLoginMetricLocalRejected);
        }

        if (!IsSmsCapabilityOpen(application.SmsLoginMode, application.SmsProfileKey))
        {
            return (RejectLocally(ReasonSmsCapability), SmsLoginMetricLocalRejected);
        }

        // ⑥ Phone (IN-17): shape is a local 400; a failed normalization is the fixed invalid-phone
        // page decided by the submitted string alone, with no OTP read and no audit.
        if (!fields.TryGetValue(FormFieldNamePhone, out var phone)
            || phone.Length > IdentityConstants.MaxSubmittedPhoneLength)
        {
            return (RejectLocally(ReasonPhoneField), SmsLoginMetricLocalRejected);
        }

        var text = NegotiatedText();
        if (!MainlandChinaPhoneNumber.TryNormalize(phone, out var phoneE164))
        {
            ApplyLoginFormContentSecurityPolicy(continuation);
            return (
                HtmlPage(
                    BuildLoginPage(
                        text, loginHandle, requestToken, new LoginNotice(NoticeTarget.Sms, AlertRole, text.InvalidPhoneNotice), SmsRegion.Empty),
                    StatusCodes.Status200OK),
                SmsLoginMetricLocalRejected);
        }

        // ⑦ Code (IN-18): opaque, never trimmed; only its presence and bound are request shape.
        if (!fields.TryGetValue(FormFieldNameOtp, out var otp)
            || otp.Length > IdentityConstants.MaxSubmittedOtpLength)
        {
            return (RejectLocally(ReasonOtpField), SmsLoginMetricLocalRejected);
        }

        var failure = new SmsLoginFailureContext(
            loginHandle, requestToken, continuation, application.AppId, phoneE164, text);

        // ⑧ Send eligibility: the same read-only decision as the send route. An ineligible phone
        // never reaches the OTP verifier, so it writes no OTP state (EV-37).
        var eligibility = await _smsAdmissions.EvaluateSendEligibilityAsync(
            continuation.AppRegistrationId, application.SmsLoginMode, phoneE164, cancellationToken);
        if (eligibility.Decision != SmsSendEligibility.Eligible)
        {
            return await FailSmsLoginAsync(
                failure, otpFailure: null, eligibility.AccountId,
                OidcSmsCodeSendService.ReasonFor(eligibility.Decision), cancellationToken);
        }

        // ⑨ The read-only OTP verification. A failure carries the conditional failed-attempt
        // change only when a current sent OTP exists; nothing is written yet.
        var verification = await _otpService.VerifyAsync(
            continuation.AppRegistrationId, phoneE164, otp, cancellationToken);
        if (verification.IsVerified != (verification.Change?.Kind == OtpVerificationChangeKind.Consume))
        {
            throw new InvalidOperationException("The OTP verification decision is inconsistent.");
        }

        if (!verification.IsVerified)
        {
            return await FailSmsLoginAsync(
                failure, verification.Change, eligibility.AccountId,
                OidcSmsLoginFailureReasons.OtpRejected, cancellationToken);
        }

        // ⑩ EV-01 revalidation after the OTP proof and before anything is consumed (SC-21): the
        // client, the exact redirect URI, and the scope decide exactly as for a Password login.
        var revalidation = await _revalidator.ValidateAsync(
            OidcContinuationRevalidation.BuildParameters(continuation, application.AppId),
            cancellationToken);
        switch (revalidation)
        {
            case OidcAuthorizationValidationResult.Accepted accepted
                when accepted.ApplicationId == continuation.AppRegistrationId:
                break;

            case OidcAuthorizationValidationResult.RedirectRejection redirect
                when redirect.ApplicationId == continuation.AppRegistrationId:
                LogOutcome(OutcomeSmsLoginRedirectRejected);
                return (
                    Redirect(OidcAuthorizationRedirect.BuildError(
                        redirect.RegisteredRedirectUri,
                        redirect.Error,
                        redirect.ErrorDescription,
                        continuation.State,
                        _jwtOptions.Issuer)),
                    SmsLoginMetricLocalRejected);

            default:
                LogOutcome(OutcomeSmsLoginClientRejected);
                return (RejectLocally(ReasonClientUnavailable), SmsLoginMetricLocalRejected);
        }

        // ⑪ EV-36: one transaction; the HTTP outcome is decided only after it.
        var completion = await _smsLoginCompletion.CompleteAsync(
            new OidcSmsLoginRequest(
                loginHandle,
                (OidcAuthorizationValidationResult.Accepted)revalidation,
                application.AppId,
                phoneE164,
                verification.Change!,
                HttpContext.GetClientIp(),
                HttpContext.GetUserAgent(),
                HttpContext.GetCorrelationId(),
                now),
            cancellationToken);
        switch (completion)
        {
            case OidcSmsLoginResult.Completed completed:
                await HttpContext.SignInAsync(
                    IdentitySessionDefaults.AuthenticationScheme,
                    IdentitySessionPrincipal.Create(completed.SessionId),
                    new AuthenticationProperties { IsPersistent = false });
                LogOutcome(OutcomeSmsLoginCompleted);
                return (
                    Redirect(OidcAuthorizationRedirect.BuildSuccess(
                        ((OidcAuthorizationValidationResult.Accepted)revalidation).RegisteredRedirectUri,
                        completed.Code,
                        continuation.State,
                        _jwtOptions.Issuer)),
                    SmsLoginMetricSuccess);

            case OidcSmsLoginResult.ContinuationUnavailable:
                // A concurrent consumption, an expiry race, or current policy drift: the single
                // local 400 of EV-03 with nothing committed.
                return (RejectLocally(ReasonContinuationUnavailable), SmsLoginMetricLocalRejected);

            default:
                return await FailSmsLoginAsync(
                    failure, otpFailure: null, eligibility.AccountId,
                    OidcSmsLoginFailureReasons.OtpRace, cancellationToken);
        }
    }

    /// <summary>
    /// Commits the <c>EV-37</c> failure unit and renders the generic SMS failure page. The page is
    /// the same whether or not the unit committed; only a closed log reason records a failed
    /// commit. No cookie is written and the <c>otp</c> input stays empty.
    /// </summary>
    private async Task<(IActionResult Result, string Outcome)> FailSmsLoginAsync(
        SmsLoginFailureContext failure,
        OtpVerificationChange? otpFailure,
        Guid? accountId,
        string reason,
        CancellationToken cancellationToken)
    {
        await _smsFailureRecorder.RecordFailureAsync(
            otpFailure,
            failure.PhoneE164,
            accountId,
            reason,
            failure.AppId,
            HttpContext.GetClientIp(),
            HttpContext.GetUserAgent(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        ApplyLoginFormContentSecurityPolicy(failure.Continuation);
        return (
            HtmlPage(
                BuildLoginPage(
                    failure.Text,
                    failure.LoginHandle,
                    failure.RequestToken,
                    new LoginNotice(NoticeTarget.Sms, AlertRole, failure.Text.SmsFailureNotice),
                    new SmsRegion(failure.PhoneE164)),
                StatusCodes.Status200OK),
            SmsLoginMetricFailure);
    }

    /// <summary>The request values every <c>EV-37</c> page is rendered from.</summary>
    private sealed record SmsLoginFailureContext(
        string LoginHandle,
        string RequestToken,
        AuthorizationRequestEntity Continuation,
        string AppId,
        string PhoneE164,
        LoginPageText Text);

    /// <summary>
    /// The <c>IN-19</c> capability gate of one application row: open exactly when SMS login is
    /// enabled and the SMS profile key is non-blank. The login page, the send route, and
    /// <c>action=sms_login</c> all decide it here.
    /// </summary>
    private static bool IsSmsCapabilityOpen(SmsLoginMode mode, string? profileKey) =>
        mode is SmsLoginMode.ManualApproval or SmsLoginMode.AutoProvision
        && !string.IsNullOrWhiteSpace(profileKey);

    /// <summary>
    /// The browser SMS send route (<c>AC-16</c>). The checks run in the canonical order — structure,
    /// continuation, antiforgery, the <c>IN-19</c> capability gate, then the <c>IN-17</c> phone —
    /// and each failure there answers the single local 400 with no send count, phone lookup, OTP
    /// write, or SMS send. An empty or unnormalizable phone re-renders the page with the fixed
    /// invalid-phone notice, decided by the submitted string alone. Every other request runs the
    /// <c>EV-35</c> unit and answers one uniform page — status 200, the rendered-form headers with
    /// no <c>Set-Cookie</c>, and the login page with the fixed send notice — whatever the phone's
    /// registration, admission, account, budget, OTP, provider, or persistence state; the true case
    /// reaches only the masked audit row, one closed log reason, and the closed metric outcome.
    /// <para>
    /// Both pages render the SMS region (<c>AC-17</c>): the uniform page fills the phone input with
    /// the normalized E.164 value and the invalid-phone page leaves it empty. The action declares no
    /// parameters for the same reason as the login POST: MVC must never read this body.
    /// </para>
    /// </summary>
    [HttpPost("sms-code")]
    [EnableRateLimiting(OidcRateLimitPolicies.SmsCode)]
    public async Task<IActionResult> SubmitSmsCodeForm()
    {
        var stopwatch = Stopwatch.StartNew();
        var (result, outcome) = await ProcessSmsCodeFormAsync();
        _metrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.LoginSmsCode, outcome);
        _metrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.LoginSmsCode,
            stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }

    private async Task<(IActionResult Result, string Outcome)> ProcessSmsCodeFormAsync()
    {
        ApplyBrowserSecurityHeaders();
        var cancellationToken = HttpContext.RequestAborted;

        // ① Structure (IN-16): no query string, the exact form content type, the bounded body,
        // and the strict parse over the four admitted fields.
        if (Request.QueryString.HasValue && Request.QueryString.Value!.Length > 0)
        {
            return (RejectLocally(ReasonQueryStructure), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        if (!IsAdmittedContentType(Request.ContentType))
        {
            return (RejectLocally(ReasonBodyStructure), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        var body = await ReadBoundedBodyAsync(MaxRequestBodyBytes + 1, cancellationToken);
        if (body.Length > MaxRequestBodyBytes
            || !TryParseStrictForm(body, AdmittedSmsCodeFormFields, out var fields))
        {
            return (RejectLocally(ReasonBodyStructure), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        // ② Continuation (IN-11 via IN-16, EV-03).
        if (!fields.TryGetValue(FormFieldNameLoginHandle, out var loginHandle))
        {
            return (RejectLocally(ReasonContinuationUnavailable), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        var now = DateTimeOffset.UtcNow;
        var continuation = await _continuations.GetActiveAsync(loginHandle, now, cancellationToken);
        if (continuation is null)
        {
            return (RejectLocally(ReasonContinuationUnavailable), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        // ③ Antiforgery (IN-14 via IN-16, PS-19), the same pair the login form validates.
        if (!TryValidateAntiforgery(fields, out var requestToken))
        {
            return (RejectLocally(ReasonAntiforgery), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        // ④ The IN-19 capability gate, read from the current row of the continuation's
        // application — the only source of the application on this route. A closed gate reveals
        // application configuration only, which the login page already shows.
        var application = await _dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.Id == continuation.AppRegistrationId)
            .Select(app => new { app.AppId, app.SmsLoginMode, app.SmsProfileKey })
            .FirstOrDefaultAsync(cancellationToken);
        if (application is null)
        {
            return (RejectLocally(ReasonClientUnavailable), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        if (!IsSmsCapabilityOpen(application.SmsLoginMode, application.SmsProfileKey))
        {
            return (RejectLocally(ReasonSmsCapability), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        // ⑤ Phone (IN-17): presence and the pre-normalization bound are request shape; a failed
        // normalization is the fixed invalid-phone page and depends on the submitted string only.
        if (!fields.TryGetValue(FormFieldNamePhone, out var phone)
            || phone.Length > IdentityConstants.MaxSubmittedPhoneLength)
        {
            return (RejectLocally(ReasonPhoneField), OidcSmsCodeSendOutcomes.LocalRejected);
        }

        var text = NegotiatedText();
        ApplyLoginFormContentSecurityPolicy(continuation);
        if (!MainlandChinaPhoneNumber.TryNormalize(phone, out var phoneE164))
        {
            return (
                HtmlPage(
                    BuildLoginPage(
                        text, loginHandle, requestToken, new LoginNotice(NoticeTarget.Sms, AlertRole, text.InvalidPhoneNotice), SmsRegion.Empty),
                    StatusCodes.Status200OK),
                OidcSmsCodeSendOutcomes.InvalidPhone);
        }

        // ⑥ EV-35: count, eligibility, OTP send, and audit. Its closed outcome never shapes the
        // response; the page reuses the submitted handle and request token and writes no cookie.
        var outcome = await _smsCodeSend.SendAsync(
            new OidcSmsCodeSendRequest(
                loginHandle,
                continuation.AppRegistrationId,
                application.AppId,
                application.SmsLoginMode,
                application.SmsProfileKey!,
                phoneE164,
                HttpContext.GetClientIp(),
                HttpContext.GetUserAgent(),
                HttpContext.GetCorrelationId(),
                now),
            cancellationToken);
        return (
            HtmlPage(
                BuildLoginPage(
                    text, loginHandle, requestToken, new LoginNotice(NoticeTarget.Sms, StatusRole, text.SmsCodeSentNotice), new SmsRegion(phoneE164)),
                StatusCodes.Status200OK),
            outcome);
    }

    /// <summary>
    /// The <c>IN-14</c>/<c>PS-19</c> antiforgery check shared by the login POST and the SMS send
    /// route: a bounded ASCII request token that validates against the separate cookie.
    /// </summary>
    private bool TryValidateAntiforgery(
        IReadOnlyDictionary<string, string> fields,
        out string requestToken)
    {
        if (fields.TryGetValue(LoginAntiforgeryDefaults.TokenFieldName, out var token)
            && token.Length > 0
            && token.Length <= LoginAntiforgeryDefaults.MaxTokenLength
            && token.All(char.IsAscii)
            && Request.Cookies.TryGetValue(LoginAntiforgeryDefaults.CookieName, out var cookieValue)
            && _antiforgery.IsValidPair(cookieValue!, token))
        {
            requestToken = token;
            return true;
        }

        requestToken = string.Empty;
        return false;
    }

    private static bool IsAdmittedContentType(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType)
            || !MediaTypeHeaderValue.TryParse(contentType, out var parsed)
            || !parsed.MediaType.Equals(FormUrlEncodedContentType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Fail closed beyond the canonical text: a charset parameter must be utf-8, and any other
        // parameter makes the submission structurally inadmissible.
        foreach (var parameter in parsed.Parameters)
        {
            if (parameter.Name.Equals(CharsetParameterName, StringComparison.OrdinalIgnoreCase))
            {
                if (!parameter.Value.Equals(Utf8Charset, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Reads at most <paramref name="limit"/> bytes; a longer body is recognizable by a full
    /// buffer and rejected without being parsed. Cancellation propagates untouched (<c>EV-18</c>).
    /// </summary>
    private async Task<byte[]> ReadBoundedBodyAsync(int limit, CancellationToken cancellationToken)
    {
        var buffer = new byte[limit];
        var total = 0;
        while (total < limit)
        {
            var read = await Request.Body.ReadAsync(
                buffer.AsMemory(total, limit - total),
                cancellationToken);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total == limit ? buffer : buffer.AsMemory(0, total).ToArray();
    }

    /// <summary>
    /// The strict <c>application/x-www-form-urlencoded</c> parse: segments split on <c>&amp;</c>
    /// with no empty segment, exactly one <c>=</c> separator per segment, percent-decoding under
    /// strict UTF-8 (an invalid byte sequence fails the whole body), <c>+</c> as space, ordinal
    /// membership in the route's admitted fields, and at most one occurrence of each.
    /// </summary>
    private static bool TryParseStrictForm(
        ReadOnlySpan<byte> body,
        string[] admittedFields,
        out Dictionary<string, string> fields)
    {
        fields = new Dictionary<string, string>(StringComparer.Ordinal);
        if (body.IsEmpty)
        {
            // An empty body carries no field; the later steps reject whatever is missing.
            return true;
        }

        var start = 0;
        while (true)
        {
            var remainder = body[start..];
            var separator = remainder.IndexOf((byte)'&');
            var end = separator >= 0 ? start + separator : body.Length;
            var segment = body[start..end];
            if (segment.IsEmpty)
            {
                return false;
            }

            var equals = segment.IndexOf((byte)'=');
            if (equals < 0)
            {
                return false;
            }

            if (!TryDecodeComponent(segment[..equals], out var name)
                || !TryDecodeComponent(segment[(equals + 1)..], out var value))
            {
                return false;
            }

            if (!admittedFields.Contains(name, StringComparer.Ordinal)
                || !fields.TryAdd(name, value))
            {
                return false;
            }

            if (separator < 0)
            {
                return true;
            }

            start = end + 1;
        }
    }

    private static bool TryDecodeComponent(ReadOnlySpan<byte> component, out string value)
    {
        value = string.Empty;
        var decoded = new byte[component.Length];
        var written = 0;
        for (var index = 0; index < component.Length; index++)
        {
            var current = component[index];
            if (current == '+')
            {
                decoded[written++] = (byte)' ';
                continue;
            }

            if (current != '%')
            {
                decoded[written++] = current;
                continue;
            }

            if (index + 2 >= component.Length
                || !TryReadHexNibble(component[index + 1], out var high)
                || !TryReadHexNibble(component[index + 2], out var low))
            {
                return false;
            }

            decoded[written++] = (byte)((high << 4) | low);
            index += 2;
        }

        try
        {
            value = StrictUtf8.GetString(decoded.AsSpan(0, written));
            return true;
        }
        catch (Exception exception) when (exception
            is DecoderFallbackException or ArgumentException)
        {
            return false;
        }
    }

    private static bool TryReadHexNibble(byte value, out int nibble)
    {
        switch (value)
        {
            case >= (byte)'0' and <= (byte)'9':
                nibble = value - '0';
                return true;
            case >= (byte)'a' and <= (byte)'f':
                nibble = value - 'a' + 10;
                return true;
            case >= (byte)'A' and <= (byte)'F':
                nibble = value - 'A' + 10;
                return true;
            default:
                nibble = 0;
                return false;
        }
    }

    /// <summary>
    /// The single login form in the negotiated language. It carries only the submitted-or-issued
    /// handle and request token as hidden fields plus the credential inputs and the two action
    /// buttons — never a stored continuation value such as the redirect URI, scope, state, nonce,
    /// or challenge, and never an echoed username or password. The field names, their order, and
    /// the button names and values are identical in every language; only the visible text differs.
    /// The single generic credential-failure notice (<c>EV-17</c>) renders the same bytes for
    /// unknown, wrong, disabled, and locked credentials, so the form never becomes an account
    /// oracle; the validator's internal reason goes to the audit row only. The SMS send route
    /// renders the same page with its fixed send or invalid-phone notice, and the SMS login with
    /// its fixed generic failure notice (<c>EV-37</c>).
    /// <para>
    /// A non-null <paramref name="smsRegion"/> — the <c>IN-19</c> gate is open — appends the SMS
    /// region as a second form (<c>AC-17</c>): its own hidden handle and request token, the
    /// <c>phone</c> input filled with the normalized value (<c>DF-16</c>) or empty, the always empty
    /// <c>otp</c> input (<c>DF-17</c>), an unnamed send button that posts the same form to the send
    /// route without constraint validation, and the <c>sms_login</c> submit button. The Password
    /// form keeps its five fields and the page stays script-free.
    /// </para>
    /// </summary>
    private static string BuildLoginPage(
        LoginPageText text,
        string loginHandle,
        string requestToken,
        LoginNotice? notice,
        SmsRegion? smsRegion)
    {
        var builder = new StringBuilder(1536);
        builder.Append("<!DOCTYPE html><html lang=\"")
            .Append(text.HtmlLang)
            .Append("\"><head><meta charset=\"utf-8\"><title>")
            .Append(text.PageTitle)
            .Append("</title>")
            .Append(HeadTail)
            .Append("</head><body><main><header class=\"page-header\"><p class=\"wordmark\">SignaCore</p><h1>")
            .Append(text.Heading)
            .Append("</h1><p class=\"description\">")
            .Append(text.Description)
            .Append("</p></header>");
        AppendFormStart(builder, notice, NoticeTarget.Password);
        builder.Append("<input type=\"hidden\" name=\"login_handle\" value=\"")
            .Append(WebUtility.HtmlEncode(loginHandle))
            .Append("\"><input type=\"hidden\" name=\"")
            .Append(LoginAntiforgeryDefaults.TokenFieldName)
            .Append("\" value=\"")
            .Append(WebUtility.HtmlEncode(requestToken))
            .Append("\">")
            .Append("<p><label for=\"username\">")
            .Append(text.UsernameLabel)
            .Append("</label> ")
            .Append("<input type=\"text\" id=\"username\" name=\"username\" ")
            .Append("autocomplete=\"username\" maxlength=\"")
            .Append(IdentityConstants.MaxUsernameLength)
            .Append("\" required></p>")
            .Append("<p><label for=\"password\">")
            .Append(text.PasswordLabel)
            .Append("</label> ")
            .Append("<input type=\"password\" id=\"password\" name=\"password\" ")
            .Append("autocomplete=\"current-password\" maxlength=\"")
            .Append(MaxPasswordLength)
            .Append("\" required></p>")
            .Append("<p class=\"actions\"><button type=\"submit\" name=\"action\" value=\"login\">")
            .Append(text.SignInButton)
            .Append("</button> ")
            // Cancel skips the browser's constraint validation of the required credential fields:
            // the server leaves on cancel before it reads them (IN-15).
            .Append("<button type=\"submit\" name=\"action\" value=\"cancel\" formnovalidate>")
            .Append(text.CancelButton)
            .Append("</button></p>")
            .Append("</form>");
        if (smsRegion is { } sms)
        {
            AppendSmsRegion(builder, text, loginHandle, requestToken, sms.Phone, notice);
        }

        builder.Append("</main></body></html>");
        return builder.ToString();
    }

    private static void AppendSmsRegion(
        StringBuilder builder,
        LoginPageText text,
        string loginHandle,
        string requestToken,
        string phone,
        LoginNotice? notice)
    {
        builder.Append("<section class=\"sms-region\" aria-labelledby=\"sms-heading\"><h2 id=\"sms-heading\">")
            .Append(text.SmsHeading)
            .Append("</h2>");
        AppendFormStart(builder, notice, NoticeTarget.Sms);
        builder.Append("<input type=\"hidden\" name=\"login_handle\" value=\"")
            .Append(WebUtility.HtmlEncode(loginHandle))
            .Append("\"><input type=\"hidden\" name=\"")
            .Append(LoginAntiforgeryDefaults.TokenFieldName)
            .Append("\" value=\"")
            .Append(WebUtility.HtmlEncode(requestToken))
            .Append("\">")
            .Append("<p><label for=\"phone\">")
            .Append(text.PhoneLabel)
            .Append("</label> ")
            .Append("<input type=\"tel\" id=\"phone\" name=\"phone\" autocomplete=\"tel\" maxlength=\"")
            .Append(IdentityConstants.MaxSubmittedPhoneLength)
            .Append("\" value=\"")
            .Append(WebUtility.HtmlEncode(phone))
            .Append("\" required></p>")
            .Append("<div class=\"otp-row\"><p class=\"otp-field\"><label for=\"otp\">")
            .Append(text.OtpLabel)
            .Append("</label> ")
            .Append("<input type=\"text\" id=\"otp\" name=\"otp\" inputmode=\"numeric\" ")
            .Append("autocomplete=\"one-time-code\" maxlength=\"")
            .Append(IdentityConstants.MaxSubmittedOtpLength)
            .Append("\" required></p>")
            // The send button carries no name, so the send route receives exactly this form's
            // handle, request token, phone, and otp (IN-16); it skips the otp constraint check.
            .Append("<button type=\"submit\" formaction=\"/oauth2/login/sms-code\" formnovalidate>")
            .Append(text.SendCodeButton)
            .Append("</button></div><p class=\"actions\">")
            .Append("<button type=\"submit\" name=\"action\" value=\"sms_login\">")
            .Append(text.SmsSignInButton)
            .Append("</button></p>")
            .Append("</form></section>");
    }

    private static void AppendFormStart(StringBuilder builder, LoginNotice? notice, NoticeTarget target)
    {
        builder.Append("<form action=\"/oauth2/login\" method=\"post\"");
        if (notice is { } shown && shown.Target == target)
        {
            var id = target == NoticeTarget.Password ? "password-notice" : "sms-notice";
            builder.Append(" aria-describedby=\"").Append(id).Append("\"><p role=\"")
                .Append(shown.Role).Append("\" id=\"").Append(id)
                .Append("\" class=\"notice\">").Append(shown.Text).Append("</p>");
        }
        else
        {
            builder.Append('>');
        }
    }

    private enum NoticeTarget { Password, Sms }

    private const string AlertRole = "alert";
    private const string StatusRole = "status";

    /// <summary>
    /// One fixed notice within its target form: an ARIA role and a fixed <see cref="LoginPageText"/>
    /// literal, never a request value.
    /// </summary>
    private readonly record struct LoginNotice(NoticeTarget Target, string Role, string Text);

    /// <summary>
    /// The SMS region of an open <c>IN-19</c> gate. <paramref name="Phone"/> is the normalized
    /// E.164 value the page re-renders into the phone input, or empty.
    /// </summary>
    private readonly record struct SmsRegion(string Phone)
    {
        public static SmsRegion Empty => new(string.Empty);
    }

    /// <summary>
    /// The local error page of one language. It depends on nothing but the language, so every
    /// rejection reason renders the same bytes, and it echoes no request value.
    /// </summary>
    private static string BuildLocalErrorPage(LoginPageText text) =>
        "<!DOCTYPE html><html lang=\"" + text.HtmlLang + "\"><head><meta charset=\"utf-8\"><title>"
        + text.ErrorTitle + "</title>" + HeadTail + "</head><body><main><header class=\"page-header\"><p class=\"wordmark\">SignaCore</p><h1>"
        + text.ErrorHeading + "</h1></header><p class=\"error-message\">" + text.ErrorMessage + "</p></main></body></html>";

    /// <summary>
    /// The text of the language negotiated from this request's <c>Accept-Language</c> header —
    /// the only input that selects the language.
    /// </summary>
    private LoginPageText NegotiatedText() =>
        LoginPageText.For(LoginPageLanguageNegotiator.Negotiate(Request.Headers.AcceptLanguage));

    /// <summary>
    /// Writes one HTML page. Its bytes depend on <c>Accept-Language</c>, so every HTML answer of
    /// this route announces that to caches with <c>Vary</c>.
    /// </summary>
    private ContentResult HtmlPage(string html, int statusCode)
    {
        Response.Headers.Vary = HeaderNames.AcceptLanguage;
        var content = Content(html, HtmlContentType, Encoding.UTF8);
        content.StatusCode = statusCode;
        return content;
    }

    private IActionResult RejectLocally(string reason)
    {
        _logger.LogInformation(
            "Login request rejected locally. Reason={Reason}, CorrelationId={CorrelationId}",
            reason,
            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
        var page = LoginPageLanguageNegotiator.Negotiate(Request.Headers.AcceptLanguage)
            == LoginPageLanguage.SimplifiedChinese
            ? SimplifiedChineseLocalErrorPage
            : EnglishLocalErrorPage;
        return HtmlPage(page, StatusCodes.Status400BadRequest);
    }

    private void LogOutcome(string outcome)
    {
        _logger.LogInformation(
            "Login request answered locally. Outcome={Outcome}, CorrelationId={CorrelationId}",
            outcome,
            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
    }

    /// <summary>
    /// Applied before any branch runs, so every <c>/oauth2/login</c> response — 200, 302, and 400
    /// alike — carries the same fixed set. The login page additionally denies framing outright,
    /// beyond the authorize endpoint's referrer and cache protections. A rendered form then
    /// widens only <c>form-action</c> (<see cref="ApplyLoginFormContentSecurityPolicy"/>).
    /// </summary>
    private void ApplyBrowserSecurityHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.XFrameOptions = "DENY";
        Response.Headers.ContentSecurityPolicy = DefaultContentSecurityPolicy;
    }

    /// <summary>
    /// Replaces the fixed policy on a rendered login form (the GET render and the credential-failure
    /// re-render). Browsers enforce the submitting document's <c>form-action</c> across the whole
    /// redirect chain of the submission, so the cancel and success redirects to the verified
    /// callback would be blocked whenever that callback is not on this origin. The form therefore
    /// also admits the origin of the continuation's stored, exactly matched redirect URI — never a
    /// value taken from the request — and nothing else.
    /// </summary>
    private void ApplyLoginFormContentSecurityPolicy(AuthorizationRequestEntity continuation)
    {
        Response.Headers.ContentSecurityPolicy =
            BuildLoginFormContentSecurityPolicy(continuation.RedirectUri);
    }

    /// <summary>
    /// Builds the form policy from the stored redirect URI. Only the <c>scheme://host[:port]</c>
    /// origin is emitted, and only when it is an http or https origin expressible as a CSP
    /// host-source (lower-case DNS name or IPv4 literal, optional explicit port). Anything else —
    /// for example an IPv6 literal loopback, which host-source syntax cannot express — keeps the
    /// fixed <c>form-action 'self'</c> policy; the page still renders and nothing is logged.
    /// </summary>
    private static string BuildLoginFormContentSecurityPolicy(string storedRedirectUri)
    {
        if (!Uri.TryCreate(storedRedirectUri, UriKind.Absolute, out var redirectUri)
            || (redirectUri.Scheme != Uri.UriSchemeHttp && redirectUri.Scheme != Uri.UriSchemeHttps))
        {
            return DefaultContentSecurityPolicy;
        }

        var origin = redirectUri.GetLeftPart(UriPartial.Authority);
        if (!FormActionOriginPattern().IsMatch(origin))
        {
            return DefaultContentSecurityPolicy;
        }

        return "default-src 'none'; style-src 'self'; form-action 'self' " + origin
            + "; frame-ancestors 'none'; base-uri 'none'";
    }

    /// <summary>
    /// The complete shape of an admitted <c>form-action</c> origin. The closed character set rules
    /// out whitespace, quotes, semicolons, commas, user info, paths, queries, and fragments, so the
    /// stored value can never inject another source or directive into the policy.
    /// </summary>
    [GeneratedRegex(@"\Ahttps?://[a-z0-9.-]+(:[0-9]{1,5})?\z", RegexOptions.CultureInvariant)]
    private static partial Regex FormActionOriginPattern();

    /// <summary>
    /// The <c>PS-19</c> cookie attributes: host-only, secure, strict same-site, root path, no
    /// domain, and no expiry — a browser session cookie written only by a successful form render.
    /// </summary>
    private static CookieOptions CreateAntiforgeryCookieOptions() => new()
    {
        Secure = true,
        HttpOnly = true,
        SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict,
        Path = "/",
        Domain = null,
        IsEssential = true
    };
}
