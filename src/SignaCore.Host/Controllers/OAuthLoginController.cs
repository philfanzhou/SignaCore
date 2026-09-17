using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// The browser-side Password identity login of the interactive Authorization Code flow:
/// <c>GET /oauth2/login</c> renders the form for an active continuation (<c>IN-10</c>) and
/// <c>POST /oauth2/login</c> processes the login or cancel submission (<c>IN-11</c>–<c>IN-15</c>).
/// </summary>
/// <remarks>
/// This slice delivers the browser surface, the antiforgery chain (<c>PS-19</c>), the local
/// result of a credential failure (<c>EV-17</c>), and the cancel exit (<c>EV-02</c>): revalidating
/// the current client and the exact redirect URI against the stored snapshot, consuming the
/// continuation, and returning the <c>access_denied</c> safe redirect. The <c>EV-01</c> success
/// transaction is still answered with the fixed local 501 and zero writes, following the
/// authorize endpoint's precedent. A missing, malformed, unknown, expired, or consumed handle
/// shares the single local 400 of <c>EV-03</c>/<c>SC-18</c>: no redirect, no credential check, no
/// failure count, no replay audit.
/// <para>
/// The controller is deliberately not an <c>[ApiController]</c> and binds no parameters: the form
/// is parsed by hand under a strict structure contract, because the automatic model-binding 400
/// would answer with JSON ProblemDetails and violate the local HTML result contract. Every
/// rejection returns one identical local page that echoes no request value, and every response
/// carries the fixed browser security headers, denies framing, and never carries a
/// <c>Location</c> except the cancel exit's <c>access_denied</c> redirect to the exact registered
/// URI. The page renders no stored continuation value — no redirect URI, scope, state, nonce, or
/// challenge — so the login surface cannot be used to read them back.
/// </para>
/// </remarks>
[Route("oauth2/login")]
public sealed class OAuthLoginController : ControllerBase
{
    /// <summary>
    /// The single local 400 body. Every structural, handle, action, antiforgery, and
    /// credential-field failure returns exactly these bytes and echoes no request value
    /// (<c>SC-19</c>: an invalid CSRF answer is indistinguishable from any other local rejection).
    /// </summary>
    private const string LocalErrorPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Invalid login request</title></head><body>"
        + "<h1>Invalid login request</h1>"
        + "<p>The login request could not be processed. Return to the application that "
        + "sent you here and start again.</p></body></html>";

    /// <summary>
    /// The fixed local "not available" page for the two outcomes this slice cannot complete: a
    /// passing credential check (<c>EV-01</c>, replaced by the orchestration slice) and a cancel
    /// submission (<c>EV-02</c>, likewise). Neither path writes anything.
    /// </summary>
    private const string NotImplementedPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Login is not available</title></head><body>"
        + "<h1>Login is not available</h1>"
        + "<p>This authorization server cannot complete an interactive login yet.</p>"
        + "</body></html>";

    /// <summary>
    /// The single generic credential-failure notice (<c>EV-17</c>). Unknown, wrong, disabled, and
    /// locked credentials render the same page byte for byte, so the form never becomes an account
    /// oracle; the validator's internal reason goes to the audit row only.
    /// </summary>
    private const string FailureNotice =
        "<p role=\"alert\">Sign-in failed. Check your username and password and try again.</p>";

    private const string HtmlContentType = "text/html; charset=utf-8";

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
    private const string OutcomeCancelRedirected = "cancel_redirected";
    private const string OutcomeCancelRejected = "cancel_rejected";
    private const string OutcomeCredentialPass = "credential_pass";
    private const string OutcomeCredentialFailure = "credential_failure";

    /// <summary>The five admitted POST form fields (<c>IN-11</c>–<c>IN-15</c>), matched ordinally.</summary>
    private static readonly string[] AdmittedFormFields =
    [
        FormFieldNameLoginHandle,
        FormFieldNameUsername,
        FormFieldNamePassword,
        LoginAntiforgeryDefaults.TokenFieldName,
        FormFieldNameAction,
    ];

    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly IAuthorizationRequestStore _continuations;
    private readonly ILoginAntiforgeryService _antiforgery;
    private readonly ValidatorFactory _validatorFactory;
    private readonly IOidcAuthorizationRequestValidator _revalidator;
    private readonly OidcLoginFailureRecorder _failureRecorder;
    private readonly IdentityDbContext _dbContext;
    private readonly JwtOptions _jwtOptions;
    private readonly ILogger<OAuthLoginController> _logger;

    public OAuthLoginController(
        IAuthorizationRequestStore continuations,
        ILoginAntiforgeryService antiforgery,
        ValidatorFactory validatorFactory,
        IOidcAuthorizationRequestValidator revalidator,
        OidcLoginFailureRecorder failureRecorder,
        IdentityDbContext dbContext,
        JwtOptions jwtOptions,
        ILogger<OAuthLoginController> logger)
    {
        _continuations = continuations;
        _antiforgery = antiforgery;
        _validatorFactory = validatorFactory;
        _revalidator = revalidator;
        _failureRecorder = failureRecorder;
        _dbContext = dbContext;
        _jwtOptions = jwtOptions;
        _logger = logger;
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

        return Content(
            BuildLoginPage(loginHandle, pair.RequestToken, showFailureNotice: false),
            HtmlContentType,
            Encoding.UTF8);
    }

    /// <summary>
    /// Processes the login form submission in the single canonical order: structure, continuation,
    /// action, antiforgery, the cancel exit, the conditional credential fields, and only then the
    /// shared Password validator. A cancel submission revalidates the current client and the exact
    /// redirect URI, consumes the continuation, and redirects <c>access_denied</c> (<c>EV-02</c>)
    /// before username and password are read at all (<c>IN-15</c>); a credential failure commits
    /// its counter and audit unit before the identical generic page is rendered
    /// (<c>EV-17</c>); a passing credential check reaches the orchestration slice's
    /// <c>EV-01</c>, answered here as the fixed local 501 with zero writes.
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
    public async Task<IActionResult> SubmitLoginForm()
    {
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
            || !TryParseStrictForm(body, out var fields))
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

        // ③ Action (IN-15): ordinal membership in the closed pair; no case folding.
        if (!fields.TryGetValue(FormFieldNameAction, out var action)
            || action is not (LoginActionValue or CancelActionValue))
        {
            return RejectLocally(ReasonAction);
        }

        // ④ Antiforgery (IN-14, PS-19): principal-independent pair validation. A failure here
        // never reaches the Password validator and never writes a failure count (SC-19).
        if (!fields.TryGetValue(LoginAntiforgeryDefaults.TokenFieldName, out var requestToken)
            || requestToken.Length == 0
            || requestToken.Length > LoginAntiforgeryDefaults.MaxTokenLength
            || !requestToken.All(char.IsAscii)
            || !Request.Cookies.TryGetValue(LoginAntiforgeryDefaults.CookieName, out var cookieValue)
            || !_antiforgery.IsValidPair(cookieValue!, requestToken))
        {
            return RejectLocally(ReasonAntiforgery);
        }

        // ⑤ The client snapshot lookup precedes both exits, because the cancel exit needs the
        // client id for its revalidation and the credential exit needs it for the failure audit.
        // The restrictive reference (PS-23) makes a missing row unreachable from a consistent
        // database; the endpoint still fails closed instead of auditing or redirecting a guess.
        var appId = await _dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.Id == continuation.AppRegistrationId)
            .Select(app => app.AppId)
            .FirstOrDefaultAsync(cancellationToken);
        if (appId is null)
        {
            return RejectLocally(ReasonClientUnavailable);
        }

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
            // EV-01 belongs to the orchestration slice: no session, no code, no cookie, no
            // consumption, no counter clear, and no success audit — the fixed local 501 with zero
            // writes.
            LogOutcome(OutcomeCredentialPass);
            return NotImplemented();
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
        return Content(
            BuildLoginPage(loginHandle, requestToken, showFailureNotice: true),
            HtmlContentType,
            Encoding.UTF8);
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
    /// membership in the five admitted fields, and at most one occurrence of each.
    /// </summary>
    private static bool TryParseStrictForm(
        ReadOnlySpan<byte> body,
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

            if (!AdmittedFormFields.Contains(name, StringComparer.Ordinal)
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
    /// The single login form. It carries only the submitted-or-issued handle and request token as
    /// hidden fields plus the credential inputs and the two action buttons — never a stored
    /// continuation value such as the redirect URI, scope, state, nonce, or challenge, and never
    /// an echoed username or password.
    /// </summary>
    private static string BuildLoginPage(string loginHandle, string requestToken, bool showFailureNotice)
    {
        var builder = new StringBuilder(1024);
        builder.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<title>Sign in</title></head><body><h1>Sign in</h1>");
        if (showFailureNotice)
        {
            builder.Append(FailureNotice);
        }

        builder.Append("<form action=\"/oauth2/login\" method=\"post\">")
            .Append("<input type=\"hidden\" name=\"login_handle\" value=\"")
            .Append(WebUtility.HtmlEncode(loginHandle))
            .Append("\"><input type=\"hidden\" name=\"")
            .Append(LoginAntiforgeryDefaults.TokenFieldName)
            .Append("\" value=\"")
            .Append(WebUtility.HtmlEncode(requestToken))
            .Append("\">")
            .Append("<p><label for=\"username\">Username</label> ")
            .Append("<input type=\"text\" id=\"username\" name=\"username\" ")
            .Append("autocomplete=\"username\" maxlength=\"")
            .Append(IdentityConstants.MaxUsernameLength)
            .Append("\" required></p>")
            .Append("<p><label for=\"password\">Password</label> ")
            .Append("<input type=\"password\" id=\"password\" name=\"password\" ")
            .Append("autocomplete=\"current-password\" maxlength=\"")
            .Append(MaxPasswordLength)
            .Append("\" required></p>")
            .Append("<p><button type=\"submit\" name=\"action\" value=\"login\">Sign in</button> ")
            .Append("<button type=\"submit\" name=\"action\" value=\"cancel\">Cancel</button></p>")
            .Append("</form></body></html>");
        return builder.ToString();
    }

    private IActionResult RejectLocally(string reason)
    {
        _logger.LogInformation(
            "Login request rejected locally. Reason={Reason}, CorrelationId={CorrelationId}",
            reason,
            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
        var content = Content(LocalErrorPage, HtmlContentType, Encoding.UTF8);
        content.StatusCode = StatusCodes.Status400BadRequest;
        return content;
    }

    private IActionResult NotImplemented()
    {
        var content = Content(NotImplementedPage, HtmlContentType, Encoding.UTF8);
        content.StatusCode = StatusCodes.Status501NotImplemented;
        return content;
    }

    private void LogOutcome(string outcome)
    {
        _logger.LogInformation(
            "Login request answered locally. Outcome={Outcome}, CorrelationId={CorrelationId}",
            outcome,
            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
    }

    /// <summary>
    /// Applied before any branch runs, so every <c>/oauth2/login</c> response — 200, 400, and 501
    /// alike — carries the same fixed set. The login page additionally denies framing outright,
    /// beyond the authorize endpoint's referrer and cache protections.
    /// </summary>
    private void ApplyBrowserSecurityHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.XFrameOptions = "DENY";
        Response.Headers.ContentSecurityPolicy =
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    }

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
