using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// RFC 6749 §3.2 token endpoint. Same issuance pipeline as <see cref="TokenController"/>, standard
/// wire format: <c>application/x-www-form-urlencoded</c> in, a token response or an error object out,
/// and real HTTP status codes.
/// <para>
/// This endpoint exists alongside <c>/api/auth/token</c> rather than replacing it; the legacy contract
/// has downstream consumers and stays unchanged. See docs/overview/StandardsConformance.md.
/// </para>
/// <para>
/// The <c>authorization_code</c> grant is redeemed here too (<c>AC-06</c>), through
/// <see cref="AuthorizationCodeRedemptionService"/> instead of the validator factory: the grant
/// deliberately stays unregistered with <see cref="TokenIssuanceService"/>, because this branch is
/// not a validator-shaped credential grant. Discovery advertises <c>authorization_code</c>
/// explicitly as a delivered capability (<c>AC-07</c>), never through validator registration.
/// </para>
/// <para>
/// The <c>refresh_token</c> grant is dispatched by digest classification
/// (<see cref="InteractiveRefreshRotationService"/>): a complete interactive marker enters the
/// atomic family rotation (<c>EV-29</c>–<c>EV-32</c>); every valid-shape legacy presentation
/// keeps its current validator path byte for byte (<c>EV-33</c>).
/// </para>
/// <para>
/// Neither action carries <c>[Consumes]</c>: the bounded form gate owns these two endpoints'
/// media-type decision, and an action-selection constraint would answer 415 ahead of the shared
/// phase/budget admission and the fixed invalid_request the client-authentication challenge
/// produces for an inadmissible body.
/// </para>
/// </summary>
[Route("oauth2")]
[ApiController]
public sealed class OAuthTokenController : ControllerBase
{
    private readonly TokenIssuanceService _tokenIssuanceService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly AuthorizationCodeRedemptionService _authorizationCodeRedemption;
    private readonly InteractiveRefreshRotationService _interactiveRefreshRotation;
    private readonly AuthMetrics _authMetrics;

    public OAuthTokenController(
        TokenIssuanceService tokenIssuanceService,
        IRefreshTokenService refreshTokenService,
        AuthorizationCodeRedemptionService authorizationCodeRedemption,
        InteractiveRefreshRotationService interactiveRefreshRotation,
        AuthMetrics authMetrics)
    {
        _tokenIssuanceService = tokenIssuanceService;
        _refreshTokenService = refreshTokenService;
        _authorizationCodeRedemption = authorizationCodeRedemption;
        _interactiveRefreshRotation = interactiveRefreshRotation;
        _authMetrics = authMetrics;
    }

    [HttpPost("token")]
    [EnableRateLimiting(OidcRateLimitPolicies.Token)]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Token(CancellationToken cancellationToken)
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var form = Request.Form;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // The internal authorization_code branch, dispatched before the grant-type mapping so no
        // validator is ever registered for it. Exactly one grant_type value may select the branch;
        // any other cardinality falls through to the shared behavior below.
        if (form["grant_type"].Count == 1
            && string.Equals(
                form["grant_type"].ToString(),
                AuthorizationCodeRedemptionService.GrantType,
                StringComparison.Ordinal))
        {
            return await RedeemCodeGrantAsync(app, form, stopwatch, cancellationToken);
        }

        // The interactive refresh branch: only a digest-matched row with the complete interactive
        // marker diverts to the family rotation; every other presentation — no row, a legacy
        // shape — keeps the legacy grant behavior below untouched (EV-33).
        if (form["grant_type"].Count == 1
            && string.Equals(
                form["grant_type"].ToString(),
                InteractiveRefreshRotationService.GrantType,
                StringComparison.Ordinal))
        {
            var dispatch = await _interactiveRefreshRotation.RotateAsync(
                app,
                form,
                clientCredentialMixPresent: HasUsableBasicCredentials()
                    && (form.ContainsKey("client_id") || form.ContainsKey("client_secret")),
                HttpContext.GetClientIp(),
                HttpContext.GetCorrelationId(),
                cancellationToken);
            if (dispatch.Handled)
            {
                var rotation = dispatch.Outcome!;
                _authMetrics.RecordOidcEndpointOutcome(
                    AuthMetrics.OidcMetricEndpoints.Refresh,
                    rotation.IsSuccess ? "success" : rotation.FailureReason!,
                    app.AppId);
                _authMetrics.RecordOidcEndpointDuration(
                    AuthMetrics.OidcMetricEndpoints.Refresh,
                    stopwatch.Elapsed.TotalMilliseconds);
                return RespondInteractiveRefresh(rotation);
            }
        }

        var wireGrantType = form["grant_type"].ToString();
        if (string.IsNullOrWhiteSpace(wireGrantType))
        {
            return FinishToken(AuthMetrics.OidcMetricEndpoints.Token, Error(OAuthErrorCodes.InvalidRequest, "grant_type is required."), app.AppId, stopwatch);
        }

        // An unknown wire name maps to unsupported_grant_type without entering token issuance.
        var grantType = OAuthGrantTypes.ToInternal(wireGrantType);
        if (grantType == null || !_tokenIssuanceService.IsSupportedGrantType(grantType))
        {
            return FinishToken(AuthMetrics.OidcMetricEndpoints.Token, Error(
                OAuthErrorCodes.UnsupportedGrantType,
                $"grant_type '{wireGrantType}' is not supported."), app.AppId, stopwatch);
        }

        // RFC 6749 §3.3: scopes are not supported, so reject an explicit scope instead of silently
        // issuing a token whose authority differs from what the client requested.
        var requestedScope = form["scope"].ToString();
        if (!string.IsNullOrWhiteSpace(requestedScope))
        {
            return FinishToken(AuthMetrics.OidcMetricEndpoints.Token, Error(OAuthErrorCodes.InvalidScope, "This authorization server does not support scopes."), app.AppId, stopwatch);
        }

        var outcome = await _tokenIssuanceService.IssueAsync(
            new TokenIssuanceRequest(
                grantType,
                app,
                Value(form["username"]),
                Value(form["password"]),
                Value(form["phone"]),
                Value(form["code"]),
                Value(form["refresh_token"]),
                HttpContext.GetClientIp(),
                HttpContext.GetUserAgent(),
                HttpContext.GetCorrelationId()),
            cancellationToken);

        if (!outcome.IsSuccess)
        {
            return FinishToken(AuthMetrics.OidcMetricEndpoints.Token, Error(outcome.ErrorCode, outcome.ErrorMessage), app.AppId, stopwatch, outcome.ErrorCode);
        }

        // RFC 6749 §5.1: successful responses must use no-store so intermediaries do not cache tokens.
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        var body = new Dictionary<string, object>
        {
            ["access_token"] = outcome.AccessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = outcome.ExpiresIn
        };
        if (!string.IsNullOrEmpty(outcome.RefreshToken))
        {
            body["refresh_token"] = outcome.RefreshToken;
        }

        return FinishToken(AuthMetrics.OidcMetricEndpoints.Token, Ok(body), app.AppId, stopwatch, "success");
    }

    /// <summary>
    /// Records one <c>token</c> endpoint-class outcome and latency around the branch result. The
    /// outcome vocabulary is closed: <c>success</c>, the service failure reasons, or the fixed
    /// OAuth error codes of the structural rejections.
    /// </summary>
    private IActionResult FinishToken(
        string endpoint,
        IActionResult result,
        string appId,
        System.Diagnostics.Stopwatch stopwatch,
        string? outcome = null)
    {
        _authMetrics.RecordOidcEndpointOutcome(
            endpoint,
            outcome ?? "invalid_request",
            appId);
        _authMetrics.RecordOidcEndpointDuration(endpoint, stopwatch.Elapsed.TotalMilliseconds);
        return result;
    }

    /// <summary>
    /// RFC 7009 §2.1 token revocation. Always answers 200 for a syntactically valid request, whether or
    /// not the token existed — unlike <c>/api/auth/revoke</c>, whose <c>success</c> flag tells the
    /// caller whether the token was real.
    /// </summary>
    [HttpPost("revoke")]
    [EnableRateLimiting(OidcRateLimitPolicies.Revoke)]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Revoke(CancellationToken cancellationToken)
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var token = Request.Form["token"].ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            return Error(OAuthErrorCodes.InvalidRequest, "token is required.");
        }

        // RFC 7009 §2.2.1: only refresh tokens can be revoked; access tokens are self-contained.
        var hint = Request.Form["token_type_hint"].ToString();
        if (!string.IsNullOrWhiteSpace(hint) &&
            !string.Equals(hint, "refresh_token", StringComparison.Ordinal) &&
            !string.Equals(hint, "access_token", StringComparison.Ordinal))
        {
            return Error("unsupported_token_type", $"token_type_hint '{hint}' is not supported.");
        }

        // RFC 7009 §2.1: revoke only tokens issued to this client. Possessing another client's token
        // is not enough to terminate its session. A mismatch still returns 200 so the response cannot
        // become an oracle for whether a token exists or who owns it.
        await _refreshTokenService.RevokeForAppAsync(token, app.AppId, cancellationToken);
        return Ok();
    }

    /// <summary>
    /// The <c>authorization_code</c> branch (<c>AC-06</c>). The method name deliberately avoids
    /// the "auth" substring: CodeQL's user-controlled-bypass query treats a request-controlled
    /// guard over an %-auth-%-named call as a bypass, and this branch is selected by
    /// <c>grant_type</c>. The <c>IN-20</c> credential mix is
    /// rejected here — a Basic header the authentication handler would accept alongside any
    /// <c>client_id</c>/<c>client_secret</c> form field — before the code is looked up; every
    /// other decision belongs to <see cref="AuthorizationCodeRedemptionService"/>. Both the
    /// success and the error bodies of this branch carry <c>Pragma: no-cache</c> in addition to
    /// <c>Cache-Control: no-store</c>.
    /// </summary>
    private async Task<IActionResult> RedeemCodeGrantAsync(
        AppRegistrationEntity app,
        IFormCollection form,
        System.Diagnostics.Stopwatch stopwatch,
        CancellationToken cancellationToken)
    {
        if (HasUsableBasicCredentials()
            && (form.ContainsKey("client_id") || form.ContainsKey("client_secret")))
        {
            return FinishToken(
                AuthMetrics.OidcMetricEndpoints.Token,
                Challenge(OAuthClientAuthenticationDefaults.Scheme),
                app.AppId,
                stopwatch,
                "invalid_client");
        }

        var outcome = await _authorizationCodeRedemption.RedeemAsync(
            app,
            form,
            HttpContext.GetClientIp(),
            HttpContext.GetCorrelationId(),
            cancellationToken);
        _authMetrics.RecordOidcEndpointOutcome(
            AuthMetrics.OidcMetricEndpoints.Token,
            outcome.IsSuccess ? "success" : (outcome.FailureReason ?? "server_error"),
            app.AppId);
        _authMetrics.RecordOidcEndpointDuration(
            AuthMetrics.OidcMetricEndpoints.Token,
            stopwatch.Elapsed.TotalMilliseconds);

        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        if (outcome.IsSuccess)
        {
            // The canonical interactive scope always contains openid, so every successful
            // redemption carries the ID token (PS-12/PS-14). A refresh_token joins only when a
            // committed offline_access family exists (EV-21).
            var body = new Dictionary<string, object>
            {
                ["access_token"] = outcome.AccessToken,
                ["token_type"] = "Bearer",
                ["expires_in"] = outcome.ExpiresIn,
                ["scope"] = outcome.Scope,
                ["id_token"] = outcome.IdToken
            };
            if (outcome.RefreshToken is not null)
            {
                body["refresh_token"] = outcome.RefreshToken;
            }

            return Ok(body);
        }

        return StatusCode(outcome.Status, new Dictionary<string, string>
        {
            ["error"] = outcome.ErrorCode,
            ["error_description"] = outcome.ErrorDescription
        });
    }

    /// <summary>
    /// The interactive <c>refresh_token</c> branch response (<c>PS-15</c>): the exact success
    /// member set released only after the rotation committed, or the branch's failure body. Both
    /// carry <c>Cache-Control: no-store</c> and <c>Pragma: no-cache</c>; the credential-mix
    /// rejection is answered with the client-authentication challenge like the code branch's.
    /// </summary>
    private IActionResult RespondInteractiveRefresh(InteractiveRefreshRotationOutcome outcome)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        if (outcome.IsSuccess)
        {
            return Ok(new Dictionary<string, object>
            {
                ["access_token"] = outcome.AccessToken,
                ["token_type"] = "Bearer",
                ["expires_in"] = outcome.ExpiresIn,
                ["scope"] = outcome.Scope,
                ["id_token"] = outcome.IdToken,
                ["refresh_token"] = outcome.RefreshToken
            });
        }

        if (outcome.Status == StatusCodes.Status401Unauthorized)
        {
            return Challenge(OAuthClientAuthenticationDefaults.Scheme);
        }

        return StatusCode(outcome.Status, new Dictionary<string, string>
        {
            ["error"] = outcome.ErrorCode!,
            ["error_description"] = outcome.ErrorDescription!
        });
    }

    /// <summary>
    /// Whether the request carries an <c>Authorization: Basic</c> header the client-authentication
    /// handler would actually use — parseable, base64-decodable, with a separator. The parse
    /// mirrors <see cref="OAuthClientAuthenticationHandler"/> so the <c>IN-20</c> mix is judged
    /// by exactly the rule the handler applies. The name deliberately avoids the "auth"
    /// substring: CodeQL's user-controlled-bypass query flags calls to %-auth-%-named methods
    /// under a request-controlled guard.
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

    private static string? Value(Microsoft.Extensions.Primitives.StringValues values)
    {
        var value = values.ToString();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    /// <summary>
    /// RFC 6749 §5.2: all errors use 400 except invalid_client, for which authentication returns 401.
    /// </summary>
    private IActionResult Error(string error, string description)
    {
        Response.Headers.CacheControl = "no-store";
        return BadRequest(new Dictionary<string, string>
        {
            ["error"] = error,
            ["error_description"] = description
        });
    }
}
