using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
/// </summary>
[Route("oauth2")]
[ApiController]
public sealed class OAuthTokenController : ControllerBase
{
    private readonly TokenIssuanceService _tokenIssuanceService;
    private readonly IRefreshTokenService _refreshTokenService;

    public OAuthTokenController(
        TokenIssuanceService tokenIssuanceService,
        IRefreshTokenService refreshTokenService)
    {
        _tokenIssuanceService = tokenIssuanceService;
        _refreshTokenService = refreshTokenService;
    }

    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Token(CancellationToken cancellationToken)
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var form = Request.Form;

        var wireGrantType = form["grant_type"].ToString();
        if (string.IsNullOrWhiteSpace(wireGrantType))
        {
            return Error(OAuthErrorCodes.InvalidRequest, "grant_type is required.");
        }

        // An unknown wire name maps to unsupported_grant_type without entering token issuance.
        var grantType = OAuthGrantTypes.ToInternal(wireGrantType);
        if (grantType == null || !_tokenIssuanceService.IsSupportedGrantType(grantType))
        {
            return Error(
                OAuthErrorCodes.UnsupportedGrantType,
                $"grant_type '{wireGrantType}' is not supported.");
        }

        // RFC 6749 §3.3: scopes are not supported, so reject an explicit scope instead of silently
        // issuing a token whose authority differs from what the client requested.
        var requestedScope = form["scope"].ToString();
        if (!string.IsNullOrWhiteSpace(requestedScope))
        {
            return Error(OAuthErrorCodes.InvalidScope, "This authorization server does not support scopes.");
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
            return Error(outcome.ErrorCode, outcome.ErrorMessage);
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

        return Ok(body);
    }

    /// <summary>
    /// RFC 7009 §2.1 token revocation. Always answers 200 for a syntactically valid request, whether or
    /// not the token existed — unlike <c>/api/auth/revoke</c>, whose <c>success</c> flag tells the
    /// caller whether the token was real.
    /// </summary>
    [HttpPost("revoke")]
    [Consumes("application/x-www-form-urlencoded")]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Revoke()
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
        await _refreshTokenService.RevokeForAppAsync(token, app.AppId);
        return Ok();
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
