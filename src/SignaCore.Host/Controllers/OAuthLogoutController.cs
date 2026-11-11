using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
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
/// the browser completion (<c>IN-35</c>/<c>IN-36</c>). ADR 0010 additionally publishes the
/// standard <c>end_session_endpoint</c> at <c>GET /oauth2/session/end</c>, which stages and
/// completes the same one-time request in a single browser visit.
/// </summary>
/// <remarks>
/// Preparation rejects with one local JSON 400 and never redirects to
/// request input. A lost response after save may leave a committed request/audit pair; the completion shares one local 400 HTML page for a missing, malformed,
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
    private const string PreparationFailureDescription = "The logout request could not be validated.";
    private const string HandleQueryName = "logout_handle";

    private readonly OidcLogoutPreparationService _preparation;
    private readonly OidcLogoutCompletionService _completion;
    private readonly OidcStandardLogoutService _standardLogout;
    private readonly IIdentitySessionCookieReader _identityCookies;
    private readonly ILogger<OAuthLogoutController> _logger;
    private readonly AuthMetrics _authMetrics;

    public OAuthLogoutController(
        OidcLogoutPreparationService preparation,
        OidcLogoutCompletionService completion,
        OidcStandardLogoutService standardLogout,
        IIdentitySessionCookieReader identityCookies,
        ILogger<OAuthLogoutController> logger,
        AuthMetrics authMetrics)
    {
        _preparation = preparation;
        _completion = completion;
        _standardLogout = standardLogout;
        _identityCookies = identityCookies;
        _logger = logger;
        _authMetrics = authMetrics;
    }

    /// <summary>
    /// The <c>IN-30</c>–<c>IN-34</c> preparation. The outer bounded form gate owns the
    /// single read and decode before authentication; this action consumes only its cached form,
    /// then re-validates the strict structure
    /// contract: admitted fields only, exactly one occurrence each. The parsed fields also answer
    /// the <c>IN-20</c> mix question: a usable Basic header alongside any form credential field.
    /// </summary>
    [HttpPost("logout/requests")]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Prepare(CancellationToken cancellationToken)
    {
        HttpContext.RequestAborted.ThrowIfCancellationRequested();
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Never fall back to a framework read: the outer gate is the only body reader.
        var form = HttpContext.Features.Get<IFormFeature>()?.Form
            ?? throw new InvalidOperationException("The bounded form gate did not provide a cached form.");
        HttpContext.RequestAborted.ThrowIfCancellationRequested();

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

        HttpContext.RequestAborted.ThrowIfCancellationRequested();
        var success = await _preparation.PrepareAsync(
            app,
            fields,
            HttpContext.GetClientIp(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        HttpContext.RequestAborted.ThrowIfCancellationRequested();
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
        cancellationToken.ThrowIfCancellationRequested();
        var profile = IdentityCookieProfile.Resolve(HttpContext);
        if (profile is null) return LocalBadRequest();

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
        Response.Cookies.Delete(profile.CsrfCookie, profile.CsrfOptions());

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
    /// The standard RP-Initiated Logout of ADR 0010 stage 1: <c>GET /oauth2/session/end</c> with
    /// a required <c>id_token_hint</c>, an optional exactly-registered
    /// <c>post_logout_redirect_uri</c>, and an optional bounded <c>state</c>. The flow validates
    /// the hint against the application named by its <c>aud</c> claim, then stages and immediately
    /// completes the same one-time request the prepared flow uses, so the <c>EV-06</c>/<c>EV-07</c>
    /// session semantics and the audit trail are identical. Every rejection is the single local
    /// 400 page; a committed success deletes the browser cookies and answers with the verified
    /// redirect (state appended byte-for-byte) or the local signed-out page. The endpoint shares
    /// the logout rate-limit policy and its source-network partition.
    /// </summary>
    [HttpGet("session/end")]
    public async Task<IActionResult> StandardEnd(CancellationToken cancellationToken)
    {
        ApplyBrowserSecurityHeaders();
        cancellationToken.ThrowIfCancellationRequested();
        var profile = IdentityCookieProfile.Resolve(HttpContext);
        if (profile is null) return LocalBadRequest();

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var query = Request.Query;
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, values) in query)
        {
            if (!OidcStandardLogoutService.AdmittedQueryFields.Contains(name)
                || values.Count != 1
                || !fields.TryAdd(name, values[0] ?? string.Empty))
            {
                return FinishSessionEnd("invalid_request", LocalBadRequest(), stopwatch);
            }
        }

        var cookieSessionId = await _identityCookies.TryReadSessionIdAsync(HttpContext);
        var result = await _standardLogout.EndAsync(
            fields,
            cookieSessionId,
            HttpContext.GetClientIp(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        if (result is null || !result.IsSuccess)
        {
            return FinishSessionEnd("invalid_request", LocalBadRequest(), stopwatch);
        }

        _authMetrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.SessionEnd, "success");
        _authMetrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.SessionEnd,
            stopwatch.Elapsed.TotalMilliseconds);

        // The same committed-completion cookie cleanup as the handle flow (PS-18 attributes,
        // explicit scheme); the management cookie is never touched.
        await HttpContext.SignOutAsync(IdentitySessionDefaults.AuthenticationScheme);
        Response.Cookies.Delete(profile.CsrfCookie, profile.CsrfOptions());

        if (result.VerifiedPostLogoutUri is null)
        {
            return Content(LocalCompletionPage, HtmlContentType);
        }

        var redirectUri = AppendState(result.VerifiedPostLogoutUri, result.State);
        _logger.LogInformation(
            "Standard logout redirect issued for a committed request. CorrelationId={CorrelationId}",
            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
        return Redirect(redirectUri);
    }

    /// <summary>
    /// Records one <c>session-end</c> endpoint-class outcome and latency around the branch
    /// result; the outcome vocabulary matches the completion endpoint's.
    /// </summary>
    private IActionResult FinishSessionEnd(
        string outcome,
        IActionResult result,
        System.Diagnostics.Stopwatch stopwatch)
    {
        _authMetrics.RecordOidcEndpointOutcome(AuthMetrics.OidcMetricEndpoints.SessionEnd, outcome);
        _authMetrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.SessionEnd,
            stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }

    /// <summary>
    /// Appends the stored state byte-for-byte using safe URI construction: the IN-33 alphabet is
    /// exactly the unreserved set, so escaping leaves valid bytes unchanged and never injects a
    /// second parameter, fragment, or host into the registered URI.
    /// </summary>
    private static string AppendState(string verifiedUri, string? state)    {
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
    /// handler would actually use — <see cref="BasicClientHeader.TryRead"/>, so the <c>IN-20</c>
    /// mix is judged by exactly the rule the handler applies.
    /// </summary>
    private bool HasUsableBasicCredentials() =>
        BasicClientHeader.TryRead(Request, out _, out _);

}
