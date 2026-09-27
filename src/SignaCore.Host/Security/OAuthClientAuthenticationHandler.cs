using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;

namespace SignaCore.Host.Security;

/// <summary>
/// RFC 6749 §2.3.1 client authentication for the <c>/oauth2/*</c> endpoints,
/// plus the token-only Public authorization-code binding by <c>client_id</c>.
/// <para>
/// Accepts <c>client_secret_basic</c> (HTTP Basic, the method the spec says clients SHOULD use) and
/// <c>client_secret_post</c> (<c>client_id</c>/<c>client_secret</c> form fields). The legacy
/// <c>X-Admin-AppId</c>/<c>X-Admin-AppSecret</c> header pair is deliberately **not** accepted here:
/// the standards-shaped surface exists precisely so that off-the-shelf clients work, and quietly
/// supporting a fourth private scheme would keep every consumer on it.
/// </para>
/// <para>
/// Per RFC 6749 §2.3.1 the Basic credentials are <c>application/x-www-form-urlencoded</c>-escaped
/// before base64 encoding, so they are unescaped here. A client that skips the escaping still works
/// for the overwhelmingly common case of credentials without reserved characters.
/// </para>
/// </summary>
public sealed class OAuthClientAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly GatewayValidationService _gatewayValidationService;
    private readonly IAppRegistrationRepository _applications;
    private const string PublicFailureItem = "signacore.oauth.public-failure";

    public OAuthClientAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        GatewayValidationService gatewayValidationService,
        IAppRegistrationRepository applications)
        : base(options, logger, encoder)
    {
        _gatewayValidationService = gatewayValidationService;
        _applications = applications;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // The outer bounded-form gate owns the standard form endpoints' body boundary: a
        // failed gate means no credential carrier may be read and no client row consulted.
        if (BoundedOidcFormReadingMiddleware.GetStatus(Context)
            is OidcBoundedFormStatus.Malformed or OidcBoundedFormStatus.Unavailable)
        {
            return AuthenticateResult.Fail(
                BoundedOidcFormReadingMiddleware.GetStatus(Context) == OidcBoundedFormStatus.Malformed
                    ? "The form request is invalid."
                    : "The request could not be processed.");
        }

        if (Request.Path == "/oauth2/token"
            && Request.HasFormContentType
            && Request.Headers.Authorization.Count == 0)
        {
            var form = await Request.ReadFormAsync(Context.RequestAborted);
            if (!form.ContainsKey("client_secret")
                && form["grant_type"].ToString() == "authorization_code")
            {
                Context.Items[PublicFailureItem] = "invalid_request";
                if (form["grant_type"].Count != 1
                    || form["grant_type"].ToString() != "authorization_code"
                    || form["client_id"].Count != 1
                    || form["client_id"].ToString().Length > IdentityConstants.MaxAppIdLength
                    || !OidcRateLimitPolicies.IsPlausibleClientId(form["client_id"].ToString()))
                {
                    return AuthenticateResult.Fail("Invalid public token request.");
                }

                var app = await _applications.GetByAppIdAsync(
                    form["client_id"].ToString(), Context.RequestAborted);
                if (app is null || !app.IsActive || app.ClientType != OidcClientType.Public
                    || app.AppSecretHash.Length != 0
                    || (app.CallbackExpiresAt.HasValue && app.CallbackExpiresAt < DateTimeOffset.UtcNow))
                {
                    Context.Items[PublicFailureItem] = "invalid_client";
                    return AuthenticateResult.Fail("Invalid public client.");
                }

                if (!app.AllowAuthorizationCode || app.AudienceMode != AudienceMode.PerApplication)
                {
                    Context.Items[PublicFailureItem] = "unauthorized_client";
                    return AuthenticateResult.Fail("Public client is not allowed to redeem codes.");
                }

                Context.Items[IdentityHeaders.ValidatedApp] = app;
                var publicIdentity = new ClaimsIdentity(
                    [new Claim(ClaimTypes.NameIdentifier, app.Id.ToString()),
                     new Claim(IdentityConstants.ClaimClientId, app.AppId)], Scheme.Name);
                return AuthenticateResult.Success(new AuthenticationTicket(
                    new ClaimsPrincipal(publicIdentity), Scheme.Name));
            }
        }

        var credentials = ReadBasicCredentials() ?? await ReadFormCredentialsAsync(Context.RequestAborted);
        if (credentials == null)
        {
            return AuthenticateResult.Fail("Missing client credentials.");
        }

        var (clientId, clientSecret) = credentials.Value;
        var validation = await _gatewayValidationService.ValidateAsync(
            clientId,
            clientSecret,
            Context.RequestAborted);
        if (!validation.IsSuccess || validation.App is null)
        {
            Logger.LogWarning(
                "OAuth client authentication failed: ClientId={ClientId}, Reason={Reason}",
                clientId,
                validation.ErrorMessage);
            return AuthenticateResult.Fail("Invalid client credentials.");
        }

        Context.Items[IdentityHeaders.ValidatedApp] = validation.App;

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, validation.App.Id.ToString()),
            new Claim(IdentityConstants.ClaimClientId, validation.App.AppId)
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        return AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    /// <summary>
    /// RFC 6749 §5.2: an invalid_client failure answered with HTTP 401 MUST carry
    /// <c>WWW-Authenticate</c>, and the body is the standard error object rather than this
    /// repository's <c>ErrorResponse</c> envelope.
    /// <para>
    /// A failed bounded-form gate maps the challenge to the fixed protocol answers instead: a
    /// malformed or oversized body is <c>400 invalid_request</c> and an unreadable body is
    /// <c>503 server_error</c> — both with fixed bodies that echo no request value and
    /// <c>no-store</c>/<c>no-cache</c> so no intermediary retains the error.
    /// </para>
    /// </summary>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Context.Items.TryGetValue(PublicFailureItem, out var publicFailure)
            && publicFailure is string publicError)
        {
            Response.StatusCode = publicError == "invalid_client"
                ? StatusCodes.Status401Unauthorized : StatusCodes.Status400BadRequest;
            await WriteFixedErrorAsync(publicError, publicError switch
            {
                "invalid_client" => "Client authentication failed.",
                "unauthorized_client" => "This client is not permitted to redeem authorization codes.",
                _ => "The token request is invalid."
            });
            return;
        }

        switch (BoundedOidcFormReadingMiddleware.GetStatus(Context))
        {
            case OidcBoundedFormStatus.Malformed:
                Response.StatusCode = StatusCodes.Status400BadRequest;
                await WriteFixedErrorAsync(
                    Domain.Validators.OAuthErrorCodes.InvalidRequest,
                    "The form request is invalid.");
                return;

            case OidcBoundedFormStatus.Unavailable:
                Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await WriteFixedErrorAsync(
                    Domain.Validators.OAuthErrorCodes.ServerError,
                    "The request could not be processed.");
                return;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers.WWWAuthenticate = $"Basic realm=\"{OAuthClientAuthenticationDefaults.Realm}\", charset=\"UTF-8\"";
        await Response.WriteAsJsonAsync(
            new Dictionary<string, string>
            {
                ["error"] = Domain.Validators.OAuthErrorCodes.InvalidClient,
                ["error_description"] = "Client authentication failed."
            },
            Context.RequestAborted);
    }

    private async Task WriteFixedErrorAsync(string error, string description)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        await Response.WriteAsJsonAsync(
            new Dictionary<string, string>
            {
                ["error"] = error,
                ["error_description"] = description
            },
            Context.RequestAborted);
    }

    private (string ClientId, string ClientSecret)? ReadBasicCredentials()
    {
        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) ||
            !AuthenticationHeaderValue.TryParse(header, out var parsed) ||
            !string.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return null;
        }

        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
        }
        catch (FormatException)
        {
            return null;
        }

        var separator = decoded.IndexOf(':');
        if (separator <= 0)
        {
            return null;
        }

        return (
            Uri.UnescapeDataString(decoded[..separator]),
            Uri.UnescapeDataString(decoded[(separator + 1)..]));
    }

    private async Task<(string ClientId, string ClientSecret)?> ReadFormCredentialsAsync(
        CancellationToken cancellationToken)
    {
        if (!Request.HasFormContentType)
        {
            return null;
        }

        var form = await Request.ReadFormAsync(cancellationToken);
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        return string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret)
            ? null
            : (clientId, clientSecret);
    }
}

public static class OAuthClientAuthenticationDefaults
{
    public const string Scheme = "OAuthClient";
    public const string Policy = "OAuthClient";
    public const string Realm = "SignaCore";
}
