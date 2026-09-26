using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using ServiceMantle.Audit;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.Management;

namespace SignaCore.Host.Management;

/// <summary>
/// The management bearer authentication scheme (#360, stage 3) and the scheme selector that
/// dispatches management requests between it and the shared management cookie.
/// </summary>
internal static class ManagementBearerAuthenticationDefaults
{
    /// <summary>The management-only bearer scheme. Never used outside the management routes.</summary>
    public const string AuthenticationScheme = "SignaCore.ManagementBearer";

    /// <summary>
    /// The policy scheme that is the host's default authenticate, challenge, and forbid scheme,
    /// and the scheme of the AdminSession and Ops policies.
    /// </summary>
    public const string SelectorScheme = "SignaCore.ManagementCredential";

    /// <summary>
    /// The policy of the explicit bearer session entries: the management bearer scheme alone (never
    /// the selector, so a cookie-only request is not authenticated by the cookie), an authenticated
    /// principal, and the Admin permission.
    /// </summary>
    public const string Policy = "ManagementBearer";

    private static readonly PathString AdminApiPath = new("/api/admin");
    private static readonly PathString ManagementApiPath = new("/management/v1");

    /// <summary>
    /// A request to a management route that carries an <c>Authorization</c> header — any value,
    /// including an empty one or several — is authenticated by the management bearer only, never
    /// by the cookie. Every other request keeps the management cookie.
    /// </summary>
    public static string SelectScheme(HttpContext context) =>
        (context.Request.Path.StartsWithSegments(AdminApiPath)
         || context.Request.Path.StartsWithSegments(ManagementApiPath))
        && context.Request.Headers.ContainsKey(HeaderNames.Authorization)
            ? AuthenticationScheme
            : ManagementSessionDefaults.AuthenticationScheme;
}

/// <summary>
/// Authenticates a management request by its management bearer credential. The credential is read
/// from the raw <c>Authorization</c> header and validated live by
/// <see cref="ManagementBearerSessionService"/>; a valid credential yields the same management
/// principal a cookie login produces.
/// <para>
/// Every rejection — several or empty headers, another scheme, a malformed, unknown, expired, or
/// revoked credential, or an account that is no longer the active bootstrap administrator —
/// answers the same fixed 401. A store that cannot answer yields the fixed 503. Neither falls back
/// to the cookie, and neither names the header value. Caller cancellation propagates.
/// </para>
/// </summary>
internal sealed class ManagementBearerAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ManagementBearerSessionService sessions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string BearerPrefix = "Bearer ";
    private const string RejectedMessage = "The management bearer credential was rejected.";
    private const string UnavailableMessage = "The management bearer credential could not be validated.";
    private const string UnauthenticatedBody = """{"errorCode":"management.bearer.unauthenticated"}""";
    private const string UnavailableBody = """{"errorCode":"management.bearer.unavailable"}""";
    private const string ForbiddenBody = """{"errorCode":"management.session.forbidden"}""";

    // Handlers are created per request, so this marks only the current request's validation.
    private bool _storeUnavailable;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var headers = Request.Headers.Authorization;
        if (headers.Count == 0)
        {
            return AuthenticateResult.NoResult();
        }

        var value = headers.Count == 1 ? headers[0] : null;
        if (value is null || !value.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.Fail(RejectedMessage);
        }

        var result = await sessions.ValidateAsync(value[BearerPrefix.Length..], Context.RequestAborted);
        switch (result.Status)
        {
            case ManagementBearerValidationStatus.Valid:
                var principal = ManagementIdentity.Create(
                    WellKnownManagementAuditOperatorSources.InteractiveAdmin,
                    result.AccountId!.Value.ToString(),
                    [ManagementPermission.Admin],
                    result.OperatorName).ToClaimsPrincipal();
                return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
            case ManagementBearerValidationStatus.Unavailable:
                _storeUnavailable = true;
                return AuthenticateResult.Fail(UnavailableMessage);
            default:
                return AuthenticateResult.Fail(RejectedMessage);
        }
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (_storeUnavailable)
        {
            return WriteAsync(StatusCodes.Status503ServiceUnavailable, UnavailableBody);
        }

        Response.Headers.WWWAuthenticate = "Bearer";
        return WriteAsync(StatusCodes.Status401Unauthorized, UnauthenticatedBody);
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        WriteAsync(StatusCodes.Status403Forbidden, ForbiddenBody);

    private Task WriteAsync(int statusCode, string body)
    {
        Response.StatusCode = statusCode;
        Response.Headers.CacheControl = "no-store";
        Response.ContentType = "application/json; charset=utf-8";
        return Response.WriteAsync(body, Context.RequestAborted);
    }
}
