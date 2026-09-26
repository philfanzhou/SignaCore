using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using ServiceMantle.Audit;
using SignaCore.Host.Audit;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;
using Microsoft.AspNetCore.RateLimiting;

namespace SignaCore.Host.Controllers;

/// <summary>
/// Browser entry point of the confidential-BFF Authorization Code flow.
/// <para>
/// This slice validates the request, routes errors, and persists the validated request as a login
/// continuation: a fully valid request leaves with a one-time <c>login_handle</c> that opens the
/// browser login form. It issues no authorization code, establishes no identity session, and reads
/// no identity cookie — every valid request goes to the login continuation. The route deliberately
/// stays out of both Discovery documents until the whole flow is complete, so no conforming client
/// is led into an unfinished flow.
/// </para>
/// <para>
/// Every parameter here is attacker-controlled. The two questions the endpoint answers are kept
/// apart: whether a trustworthy destination exists at all, and only then what protocol result may
/// be sent there.
/// </para>
/// </summary>
[Route("oauth2")]
[ApiController]
[EnableRateLimiting(OidcRateLimitPolicies.Authorize)]
public sealed class OAuthAuthorizationController : ControllerBase
{
    /// <summary>
    /// The single local response body. Every local rejection returns exactly these bytes, so an
    /// unknown client, an inactive client, a client without the interactive capability, and an
    /// unmatched redirect URI are indistinguishable from outside. It echoes no request value, which
    /// is also why it needs no contextual encoding of submitted text.
    /// </summary>
    private const string LocalErrorPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Invalid authorization request</title></head><body>"
        + "<h1>Invalid authorization request</h1>"
        + "<p>The authorization request could not be processed. Return to the application that "
        + "sent you here and start again.</p></body></html>";

    private const string HtmlContentType = "text/html; charset=utf-8";

    private const string AuditAction = "oidc.authorize.validated";
    private const string AuditTargetType = "OidcAuthorizationRequest";
    private const string AcceptedOutcome = "accepted";

    // The closed reuse outcome names written to the logs: aggregates only, with the correlation
    // id; no session id, cookie, account, scope, state, nonce, redirect URI, or code value.
    private const string SessionReusedOutcome = "session_reused";
    private const string SessionUnusableOutcome = "session_unusable";

    private readonly IOidcAuthorizationRequestValidator _validator;
    private readonly IAuthorizationRequestStore _authorizationRequestStore;
    private readonly IIdentitySessionCookieReader _identitySessionCookieReader;
    private readonly OidcAuthorizationSessionReuseService _sessionReuse;
    private readonly IManagementAuditWriter _auditWriter;
    private readonly IUnitOfWork _unitOfWork;
    private readonly AuthMetrics _metrics;
    private readonly JwtOptions _jwtOptions;
    private readonly ILogger<OAuthAuthorizationController> _logger;

    public OAuthAuthorizationController(
        IOidcAuthorizationRequestValidator validator,
        IAuthorizationRequestStore authorizationRequestStore,
        IIdentitySessionCookieReader identitySessionCookieReader,
        OidcAuthorizationSessionReuseService sessionReuse,
        IManagementAuditWriter auditWriter,
        IUnitOfWork unitOfWork,
        AuthMetrics metrics,
        JwtOptions jwtOptions,
        ILogger<OAuthAuthorizationController> logger)
    {
        _validator = validator;
        _authorizationRequestStore = authorizationRequestStore;
        _identitySessionCookieReader = identitySessionCookieReader;
        _sessionReuse = sessionReuse;
        _auditWriter = auditWriter;
        _unitOfWork = unitOfWork;
        _metrics = metrics;
        _jwtOptions = jwtOptions;
        _logger = logger;
    }

    /// <summary>
    /// RFC 6749 §4.1.1 authorization request. Only <c>GET</c> exists in this phase; there is no
    /// <c>POST</c> form-post variant and no fragment response mode.
    /// <para>
    /// The login continuation itself must be a local URL. The request's <c>PathBase</c> is the only
    /// request-controlled input of that destination, so a prefix that cannot form a local URL — for
    /// example a scheme-relative mount — is refused with the fixed local error before anything is
    /// written: no <c>Location</c>, no continuation row, and no accepted audit row. Registered
    /// cross-origin application callbacks are unaffected; they keep their exact-URI validation.
    /// </para>
    /// </summary>
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize(CancellationToken cancellationToken)
    {
        ApplyBrowserSecurityHeaders();

        var parameters = new OidcAuthorizationParameters(
            Request.Query.Select(entry =>
                new KeyValuePair<string, IReadOnlyList<string>>(
                    entry.Key,
                    ToValues(entry.Value))));

        var result = await _validator.ValidateAsync(parameters, cancellationToken);

        switch (result)
        {
            case OidcAuthorizationValidationResult.LocalRejection local:
                // No application was resolved, so there is no bounded subject to audit and no
                // registered client id that could be a metric label. Unauthenticated traffic must
                // not be able to grow the audit table; the counter carries the volume instead.
                _metrics.RecordOidcAuthorizeOutcome(local.Reason);
                _logger.LogInformation(
                    "Authorization request rejected locally. Reason={Reason}, CorrelationId={CorrelationId}",
                    local.Reason,
                    LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
                return LocalError();

            case OidcAuthorizationValidationResult.RedirectRejection redirect:
                _metrics.RecordOidcAuthorizeOutcome(redirect.Error, redirect.ClientId);
                await RecordAuditAsync(redirect.ApplicationId, redirect.Error, cancellationToken);
                return Redirect(OidcAuthorizationRedirect.BuildError(
                    redirect.RegisteredRedirectUri,
                    redirect.Error,
                    redirect.ErrorDescription,
                    redirect.State,
                    _jwtOptions.Issuer));

            case OidcAuthorizationValidationResult.Accepted accepted:
                _metrics.RecordOidcAuthorizeOutcome(AcceptedOutcome, accepted.ClientId);
                var now = DateTimeOffset.UtcNow;
                // The identity cookie may name a still-live server-side session: when the reuse
                // transaction commits, the browser leaves with a code and no login continuation;
                // when it rolls back, the unchanged continuation path runs afterwards, so every
                // accepted request still commits exactly one continuation-shaped audit row.
                var candidateSessionId = await _identitySessionCookieReader
                    .TryReadSessionIdAsync(HttpContext);
                if (candidateSessionId is not null)
                {
                    var reusedCode = await _sessionReuse.TryIssueAsync(
                        accepted,
                        candidateSessionId.Value,
                        now,
                        HttpContext.GetClientIp(),
                        HttpContext.GetCorrelationId(),
                        cancellationToken);
                    if (reusedCode is not null)
                    {
                        _logger.LogInformation(
                            "Authorization request answered with session reuse. Outcome={Outcome}, CorrelationId={CorrelationId}",
                            SessionReusedOutcome,
                            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
                        return Redirect(OidcAuthorizationRedirect.BuildSuccess(
                            accepted.RegisteredRedirectUri,
                            reusedCode,
                            accepted.State,
                            _jwtOptions.Issuer));
                    }

                    _logger.LogInformation(
                        "Authorization request fell back to the login continuation. Outcome={Outcome}, CorrelationId={CorrelationId}",
                            SessionUnusableOutcome,
                            LogValueSanitizer.Sanitize(HttpContext.GetCorrelationId()));
                }

                // The login continuation must stay a same-origin relative path. PathBase is
                // request-controlled state, so the destination is validated as a local URL before
                // anything is written: a prefix that cannot form a local URL answers the fixed
                // local error with no Location, no continuation, and no audit row, and the original
                // prefix value is never echoed or logged.
                var loginPath = $"{Request.PathBase}/oauth2/login";
                if (!Url.IsLocalUrl(loginPath))
                {
                    return LocalError();
                }

                // The accepted audit row is only staged here; the continuation store's single
                // SaveChanges commits the continuation row and the audit row as one unit, so a
                // failure between them cannot leave half of the outcome behind.
                await StageAuditAsync(accepted.ApplicationId, AcceptedOutcome, cancellationToken);
                var creation = await _authorizationRequestStore.CreateAsync(
                    accepted, now, cancellationToken);
                // A same-origin relative location only: no scheme or host is taken from the
                // request, the handle is the sole query field the login page receives, and the
                // final executor re-asserts locality by refusing any non-local destination.
                return LocalRedirect(
                    $"{loginPath}?login_handle={Uri.EscapeDataString(creation.LoginHandle)}");

            default:
                throw new InvalidOperationException(
                    $"Unhandled authorization validation result '{result.GetType().Name}'.");
        }
    }

    private IActionResult LocalError()
    {
        var content = Content(LocalErrorPage, HtmlContentType, Encoding.UTF8);
        return WithStatus(content, StatusCodes.Status400BadRequest);
    }

    private static IActionResult WithStatus(ContentResult content, int statusCode)
    {
        content.StatusCode = statusCode;
        return content;
    }

    /// <summary>
    /// Applied before any branch runs, so a local error, a safe redirect, and a valid request all
    /// carry them. A referrer would otherwise leak the whole authorization query to the redirect
    /// target's own resources.
    /// </summary>
    private void ApplyBrowserSecurityHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
    }

    /// <summary>
    /// Records the outcome for a resolved application. The target is the application record id and
    /// the description is a closed-set outcome name; no state, nonce, challenge, scope, or raw URI
    /// is written. The staged row is committed by whichever single <c>SaveChanges</c> owns the
    /// endpoint's write unit: the redirect-rejection path commits it immediately, while the
    /// accepted path leaves the commit to the continuation store's single save so the continuation
    /// row and the audit row commit atomically.
    /// </summary>
    private async Task StageAuditAsync(Guid applicationId, string outcome, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await ManagementActionAudit.RecordAsync(
            _auditWriter,
            ManagementActionAudit.SystemSource,
            AuditAction,
            AuditTargetType,
            applicationId.ToString("D"),
            actorId: null,
            actorName: null,
            description: outcome,
            clientIp: HttpContext.GetClientIp(),
            correlationId: HttpContext.GetCorrelationId(),
            outcome: AcceptedOutcome.Equals(outcome, StringComparison.Ordinal)
                ? ManagementAuditOutcome.Success
                : ManagementAuditOutcome.Denied,
            cancellationToken: cancellationToken);
    }

    private async Task RecordAuditAsync(Guid applicationId, string outcome, CancellationToken cancellationToken)
    {
        await StageAuditAsync(applicationId, outcome, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private static IReadOnlyList<string> ToValues(StringValues values)
    {
        var result = new List<string>(values.Count);
        foreach (var value in values)
        {
            result.Add(value ?? string.Empty);
        }

        return result;
    }
}
