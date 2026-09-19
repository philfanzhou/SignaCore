using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// The prepared logout of the interactive flow: <c>POST /oauth2/logout/requests</c> is the
/// authenticated BFF preparation (<c>IN-30</c>–<c>IN-34</c>) and <c>GET /oauth2/logout</c> is
/// the browser completion (<c>IN-35</c>/<c>IN-36</c>). The wire shape is deliberately not
/// RP-Initiated Logout, so Discovery publishes no <c>end_session_endpoint</c> (<c>AC-10</c>).
/// </summary>
/// <remarks>
/// Every preparation failure is one local JSON 400 that creates no row and never redirects to
/// request input; the completion shares one local 400 HTML page for a missing, malformed,
/// expired, or consumed handle (<c>SC-18</c>). After a committed completion the identity cookie
/// is deleted through the explicit identity scheme (<c>PS-18</c>); the shared ServiceMantle
/// management cookie is never touched. A <c>Location</c> appears only for the verified,
/// registered post-logout URI of a committed request, with the stored state appended
/// byte-for-byte; every other success renders the local completion page.
/// </remarks>
[Route("oauth2")]
[EnableRateLimiting(OidcRateLimitPolicies.Logout)]
public sealed class OAuthLogoutController : ControllerBase
{
    /// <summary>
    /// The single local completion page. It renders no stored request value and is the answer of
    /// both the <c>EV-06</c> and <c>EV-07</c> successes without a redirect.
    /// </summary>
    private const string LocalCompletionPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Signed out</title></head><body>"
        + "<h1>You are signed out</h1>"
        + "<p>Return to the application that sent you here.</p></body></html>";

    private const string LocalErrorPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Invalid logout request</title></head><body>"
        + "<h1>Invalid logout request</h1>"
        + "<p>The logout request could not be processed. Return to the application that "
        + "sent you here and start again.</p></body></html>";

    private const string HtmlContentType = "text/html; charset=utf-8";
    private const string FormUrlEncodedContentType = "application/x-www-form-urlencoded";
    private const string CharsetParameterName = "charset";
    private const string Utf8Charset = "utf-8";

    /// <summary>The canonical 16 KiB bound of the preparation form body (<c>IN-30</c>).</summary>
    private const int MaxRequestBodyBytes = 16 * 1024;

    private const string PreparationFailureDescription = "The logout request could not be validated.";
    private const string HandleQueryName = "logout_handle";

    private readonly OidcLogoutPreparationService _preparation;
    private readonly OidcLogoutCompletionService _completion;
    private readonly IIdentitySessionCookieReader _identityCookies;
    private readonly ILogger<OAuthLogoutController> _logger;
    private readonly AuthMetrics _authMetrics;

    public OAuthLogoutController(
        OidcLogoutPreparationService preparation,
        OidcLogoutCompletionService completion,
        IIdentitySessionCookieReader identityCookies,
        ILogger<OAuthLogoutController> logger,
        AuthMetrics authMetrics)
    {
        _preparation = preparation;
        _completion = completion;
        _identityCookies = identityCookies;
        _logger = logger;
        _authMetrics = authMetrics;
    }

    /// <summary>
    /// The <c>IN-30</c>–<c>IN-34</c> preparation. The body is bounded by
    /// <see cref="RequestSizeLimitAttribute"/> and parsed through the shared form feature — the
    /// same buffered path the token endpoint uses — then re-validated under the strict structure
    /// contract: admitted fields only, exactly one occurrence each. The parsed fields also answer
    /// the <c>IN-20</c> mix question: a usable Basic header alongside any form credential field.
    /// </summary>
    [HttpPost("logout/requests")]
    [Consumes("application/x-www-form-urlencoded")]
    [RequestSizeLimit(MaxRequestBodyBytes)]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Prepare(CancellationToken cancellationToken)
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        if (!IsAcceptedFormContentType())
        {
            return FinishLogoutPrepare("invalid_request", PreparationFailure(), app.AppId, stopwatch);
        }

        IFormCollection form;
        try
        {
            form = await Request.ReadFormAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is InvalidDataException or OperationCanceledException)
        {
            return FinishLogoutPrepare("invalid_request", PreparationFailure(), app.AppId, stopwatch);
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, values) in form)
        {
            // The strict structure: unknown fields and repeated fields are both rejected.
            if (!OidcLogoutPreparationService.AdmittedFormFields.Contains(name)
                || values.Count != 1
                || !fields.TryAdd(name, values[0] ?? string.Empty))
            {
                return FinishLogoutPrepare("invalid_request", PreparationFailure(), app.AppId, stopwatch);
            }
        }

        if (HasUsableBasicCredentials()
            && (fields.ContainsKey("client_id") || fields.ContainsKey("client_secret")))
        {
            return FinishLogoutPrepare(
                "invalid_client",
                Challenge(OAuthClientAuthenticationDefaults.Scheme),
                app.AppId,
                stopwatch);
        }

        var success = await _preparation.PrepareAsync(
            app,
            fields,
            HttpContext.GetClientIp(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        if (success is null)
        {
            return FinishLogoutPrepare("invalid_request", PreparationFailure(), app.AppId, stopwatch);
        }

        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        return FinishLogoutPrepare(
            "success",
            Ok(new Dictionary<string, string>
            {
                ["logout_uri"] = success.LogoutUri
            }),
            app.AppId,
            stopwatch);
    }

    /// <summary>
    /// Records one <c>logout-complete</c> endpoint-class outcome and latency around the branch
    /// result. The browser completion surface resolves no client identity, so no client label is
    /// attached.
    /// </summary>
    private IActionResult FinishLogoutComplete(
        string outcome,
        IActionResult result,
        System.Diagnostics.Stopwatch stopwatch)
    {
        _authMetrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.LogoutComplete, outcome);
        _authMetrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.LogoutComplete,
            stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }

    /// <summary>
    /// Records one <c>logout-prepare</c> endpoint-class outcome and latency around the branch
    /// result; the outcome vocabulary is the closed set above.
    /// </summary>
    private IActionResult FinishLogoutPrepare(
        string outcome,
        IActionResult result,
        string appId,
        System.Diagnostics.Stopwatch stopwatch)
    {
        _authMetrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.LogoutPrepare, outcome, appId);
        _authMetrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.LogoutPrepare,
            stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }

    /// <summary>
    /// The <c>IN-35</c>/<c>IN-36</c> browser completion. The handle is the sole supported query
    /// field; no body, ID token, redirect URI, state, or client credential is read here. After a
    /// committed result the identity cookie is deleted through the explicit identity scheme and
    /// the answer is either the exact stored redirect with the state appended byte-for-byte or
    /// the local completion page — identically for the <c>EV-06</c> and <c>EV-07</c> paths.
    /// </summary>
    [HttpGet("logout")]
    public async Task<IActionResult> Complete(CancellationToken cancellationToken)
    {
        ApplyBrowserSecurityHeaders();

        // IN-35: exactly one query field, the 43-character handle; anything else is the single
        // local 400 with no redirect and no invented consumption.
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var query = Request.Query;
        if (query.Count != 1
            || !query.TryGetValue(HandleQueryName, out var values)
            || values.Count != 1
            || !IsLogoutHandleShape(values[0]))
        {
            return FinishLogoutComplete("invalid_request", LocalBadRequest(), stopwatch);
        }

        var cookieSessionId = await _identityCookies.TryReadSessionIdAsync(HttpContext);
        var result = await _completion.CompleteAsync(
            values[0]!,
            cookieSessionId,
            HttpContext.GetClientIp(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        if (!result.IsSuccess)
        {
            return FinishLogoutComplete("invalid_request", LocalBadRequest(), stopwatch);
        }

        _authMetrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.LogoutComplete, "success");
        _authMetrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.LogoutComplete,
            stopwatch.Elapsed.TotalMilliseconds);

        // The cookie deletion follows the committed result (PS-18 attributes, explicit scheme);
        // it never runs for an uncommitted unit and never touches the management cookie.
        await HttpContext.SignOutAsync(IdentitySessionDefaults.AuthenticationScheme);

        if (result.VerifiedPostLogoutUri is null)
        {
            return Content(LocalCompletionPage, HtmlContentType);
        }

        var redirectUri = AppendState(result.VerifiedPostLogoutUri, result.State);
        _logger.LogInformation(
            "Logout redirect issued for a committed request. CorrelationId={CorrelationId}",
            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
        return Redirect(redirectUri);
    }

    /// <summary>
    /// Appends the stored state byte-for-byte using safe URI construction: the IN-33 alphabet is
    /// exactly the unreserved set, so escaping leaves valid bytes unchanged and never injects a
    /// second parameter, fragment, or host into the registered URI.
    /// </summary>
    private static string AppendState(string verifiedUri, string? state)
    {
        if (state is null)
        {
            return verifiedUri;
        }

        var separator = verifiedUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        return $"{verifiedUri}{separator}state={Uri.EscapeDataString(state)}";
    }

    private IActionResult PreparationFailure()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        return BadRequest(new Dictionary<string, string>
        {
            ["error"] = "invalid_request",
            ["error_description"] = PreparationFailureDescription
        });
    }

    /// <summary>
    /// The strict content-type gate of the manual parse: exactly the form media type, and a
    /// charset parameter only when it names UTF-8 — the strict decoder assumes UTF-8 bytes.
    /// </summary>
    private bool IsAcceptedFormContentType()
    {
        if (!MediaTypeHeaderValue.TryParse(Request.ContentType, out var contentType))
        {
            return false;
        }

        if (!string.Equals(contentType.MediaType, FormUrlEncodedContentType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return contentType.Parameters.FirstOrDefault(parameter =>
                string.Equals(parameter.Name, CharsetParameterName, StringComparison.OrdinalIgnoreCase))
            is not { } charset
            || string.Equals(charset.Value, Utf8Charset, StringComparison.OrdinalIgnoreCase);
    }

    private ContentResult LocalBadRequest()
    {
        Response.StatusCode = StatusCodes.Status400BadRequest;
        return Content(LocalErrorPage, HtmlContentType);
    }

    /// <summary>
    /// Applied first on every completion response — 400, 302, and 200 alike — so no logout
    /// answer is cacheable, referable, or frameable.
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

    private static bool IsLogoutHandleShape(string? value) =>
        value is not null
        && value.Length == IdentityConstants.LogoutHandleLength
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    /// <summary>
    /// Whether the request carries an <c>Authorization: Basic</c> header the client-authentication
    /// handler would actually use — the same parse the handler applies, so the <c>IN-20</c> mix
    /// is judged by exactly that rule.
    /// </summary>
    private bool HasUsableBasicCredentials()
    {
        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header)
            || !AuthenticationHeaderValue.TryParse(header, out var parsed)
            || !string.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return false;
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
            return decoded.IndexOf(':') > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

}
