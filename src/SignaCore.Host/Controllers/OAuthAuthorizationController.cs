using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;

namespace SignaCore.Host.Controllers;

/// <summary>
/// Browser entry point of the confidential-BFF Authorization Code flow.
/// <para>
/// This slice validates the request and routes errors; it issues no authorization code and no
/// success redirect, and it establishes no identity session. The route deliberately stays out of
/// both Discovery documents until the whole flow is complete, so no conforming client is led into
/// an unfinished flow.
/// </para>
/// <para>
/// Every parameter here is attacker-controlled. The two questions the endpoint answers are kept
/// apart: whether a trustworthy destination exists at all, and only then what protocol result may
/// be sent there.
/// </para>
/// </summary>
[Route("oauth2")]
[ApiController]
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

    /// <summary>
    /// A request that passes every protocol check still cannot proceed: the identity session,
    /// login continuation, and code issuance belong to the orchestration slice. Answering locally
    /// keeps that gap from looking like a protocol error the client should react to.
    /// </summary>
    private const string NotImplementedPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Authorization is not available</title></head><body>"
        + "<h1>Authorization is not available</h1>"
        + "<p>This authorization server cannot complete an interactive authorization request "
        + "yet.</p></body></html>";

    private const string HtmlContentType = "text/html; charset=utf-8";

    private const string AuditAction = "oidc.authorize.validated";
    private const string AuditTargetType = "OidcAuthorizationRequest";
    private const string AcceptedOutcome = "accepted";

    private readonly IOidcAuthorizationRequestValidator _validator;
    private readonly IAuditService _auditService;
    private readonly AuthMetrics _metrics;
    private readonly JwtOptions _jwtOptions;
    private readonly ILogger<OAuthAuthorizationController> _logger;

    public OAuthAuthorizationController(
        IOidcAuthorizationRequestValidator validator,
        IAuditService auditService,
        AuthMetrics metrics,
        JwtOptions jwtOptions,
        ILogger<OAuthAuthorizationController> logger)
    {
        _validator = validator;
        _auditService = auditService;
        _metrics = metrics;
        _jwtOptions = jwtOptions;
        _logger = logger;
    }

    /// <summary>
    /// RFC 6749 §4.1.1 authorization request. Only <c>GET</c> exists in this phase; there is no
    /// <c>POST</c> form-post variant and no fragment response mode.
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
                _metrics.RecordOidcAuthorizeOutcome(local.Reason, AuthMetrics.UnregisteredClient);
                _logger.LogInformation(
                    "Authorization request rejected locally. Reason={Reason}, CorrelationId={CorrelationId}",
                    local.Reason,
                    HttpContext.GetCorrelationId());
                return LocalError();

            case OidcAuthorizationValidationResult.RedirectRejection redirect:
                _metrics.RecordOidcAuthorizeOutcome(redirect.Error, redirect.ClientId);
                await RecordAuditAsync(redirect.ApplicationId, redirect.Error, cancellationToken);
                return Redirect(BuildErrorRedirect(redirect));

            case OidcAuthorizationValidationResult.Accepted accepted:
                _metrics.RecordOidcAuthorizeOutcome(AcceptedOutcome, accepted.ClientId);
                await RecordAuditAsync(accepted.ApplicationId, AcceptedOutcome, cancellationToken);
                return WithStatus(
                    Content(NotImplementedPage, HtmlContentType, Encoding.UTF8),
                    StatusCodes.Status501NotImplemented);

            default:
                throw new InvalidOperationException(
                    $"Unhandled authorization validation result '{result.GetType().Name}'.");
        }
    }

    /// <summary>
    /// Builds the safe redirect of <c>PS-17</c>: the exact registered URI plus <c>error</c>, a
    /// closed-set English <c>error_description</c>, the byte-for-byte <c>state</c> when the request
    /// supplied a usable one, and the issuer. There is no fragment or form-post response mode.
    /// </summary>
    private string BuildErrorRedirect(OidcAuthorizationValidationResult.RedirectRejection rejection)
    {
        // The registered URI may already carry a query, which registration preserves verbatim.
        var separator = rejection.RegisteredRedirectUri.Contains('?', StringComparison.Ordinal)
            ? '&'
            : '?';

        var builder = new StringBuilder(rejection.RegisteredRedirectUri);
        builder.Append(separator);
        AppendParameter(builder, "error", rejection.Error, first: true);
        AppendParameter(builder, "error_description", rejection.ErrorDescription, first: false);
        if (rejection.State is not null)
        {
            // The IN-05 alphabet is exactly the URI unreserved set, so escaping leaves a valid
            // state unchanged and the client sees the bytes it sent.
            AppendParameter(builder, "state", rejection.State, first: false);
        }

        AppendParameter(builder, "iss", _jwtOptions.Issuer, first: false);
        return builder.ToString();
    }

    private static void AppendParameter(StringBuilder builder, string name, string value, bool first)
    {
        if (!first)
        {
            builder.Append('&');
        }

        builder.Append(name).Append('=').Append(Uri.EscapeDataString(value));
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
    /// is written. Audit persistence is not part of a transaction here — this endpoint commits no
    /// state of its own — so a failed audit write is logged by the audit service and does not turn
    /// a validated rejection into a server error.
    /// </summary>
    private Task RecordAuditAsync(Guid applicationId, string outcome, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _auditService.RecordActionAsync(
            AuditAction,
            AuditTargetType,
            applicationId.ToString("D"),
            actorId: null,
            actorName: null,
            description: outcome,
            clientIp: HttpContext.GetClientIp(),
            correlationId: HttpContext.GetCorrelationId());
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
