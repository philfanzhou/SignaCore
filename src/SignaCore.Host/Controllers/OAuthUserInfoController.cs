using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// The scope-controlled OIDC UserInfo endpoint (<c>AC-08</c>/<c>PS-16</c>): a server-to-server
/// projection for a confidential BFF holding one interactive access token. Only <c>GET</c> with a
/// single <c>Authorization: Bearer</c> header is admitted (<c>IN-28</c>); every validation and
/// live-state decision belongs to <see cref="OidcUserInfoService"/> (<c>IN-29</c>). The endpoint
/// is anonymous at the ASP.NET layer on purpose — the Bearer credential is the only
/// authentication, and the management API's JWT bearer configuration is deliberately not reused.
/// <para>
/// The endpoint opts out of the host's global <c>AdminWeb</c> CORS policy explicitly: no
/// <c>Access-Control-Allow-*</c> header may appear and no preflight is answered, so a browser can
/// never read a profile directly — the BFF proxy is the only intended consumer (<c>DF-15</c>).
/// Every response carries <c>Cache-Control: no-store</c>, <c>Pragma: no-cache</c>, and a
/// restrictive referrer policy.
/// </para>
/// </summary>
[Route("oauth2")]
[ApiController]
public sealed class OAuthUserInfoController : ControllerBase
{
    private const string BearerChallenge = "Bearer";

    // Fixed English descriptions (RFC 6750 §3): they name the class, never the failed
    // cryptographic, binding, account, application, or session predicate.
    private const string InvalidRequestDescription =
        "The access token request is malformed.";
    private const string InvalidTokenDescription =
        "The access token is invalid or expired.";
    private const string InsufficientScopeDescription =
        "The access token does not carry the required scope.";

    private readonly OidcUserInfoService _userInfo;

    public OAuthUserInfoController(OidcUserInfoService userInfo)
    {
        _userInfo = userInfo;
    }

    [HttpGet("userinfo")]
    [AllowAnonymous]
    public async Task<IActionResult> UserInfo(CancellationToken cancellationToken)
    {
        // IN-28: the alternate carriers are rejected before any token or state is read. A query
        // or form body on a GET is itself an alternate-carrier attempt.
        var alternateCarrierPresent = Request.Query.ContainsKey("access_token")
            || Request.Query.ContainsKey("id_token")
            || Request.Query.ContainsKey("refresh_token")
            || Request.Query.ContainsKey("client_secret")
            || Request.HasFormContentType;

        var outcome = await _userInfo.ReadAsync(
            Request.Headers.Authorization,
            alternateCarrierPresent,
            cancellationToken);

        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        if (outcome.IsSuccess)
        {
            // PS-16: the closed response set — sub always; name/nickname only when profile
            // survived the token-scope/current-allow-list intersection. No invented empty fields.
            var body = new Dictionary<string, string>
            {
                ["sub"] = outcome.Subject
            };
            if (outcome.Name is not null)
            {
                body["name"] = outcome.Name;
            }

            if (outcome.Nickname is not null)
            {
                body["nickname"] = outcome.Nickname;
            }

            return Ok(body);
        }

        return outcome.Rejection switch
        {
            OidcUserInfoRejection.MissingBearer => Reject(
                StatusCodes.Status401Unauthorized, BearerChallenge),
            OidcUserInfoRejection.InvalidRequest => Reject(
                StatusCodes.Status400BadRequest,
                $"{BearerChallenge} error=\"invalid_request\", error_description=\"{InvalidRequestDescription}\""),
            OidcUserInfoRejection.InsufficientScope => Reject(
                StatusCodes.Status403Forbidden,
                $"{BearerChallenge} error=\"insufficient_scope\", error_description=\"{InsufficientScopeDescription}\""),
            _ => Reject(
                StatusCodes.Status401Unauthorized,
                $"{BearerChallenge} error=\"invalid_token\", error_description=\"{InvalidTokenDescription}\"")
        };
    }

    /// <summary>
    /// The empty-body rejection with its <c>WWW-Authenticate</c> row — the bare <c>Bearer</c>
    /// challenge for the missing-header row, the <c>error</c> form for the rest (RFC 6750 §3).
    /// </summary>
    private IActionResult Reject(int statusCode, string challenge)
    {
        Response.Headers["WWW-Authenticate"] = challenge;
        return StatusCode(statusCode);
    }
}
