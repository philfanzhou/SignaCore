using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SignaCore.Database;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;

namespace SignaCore.Host.Security;

/// <summary>
/// RFC 6749 §2.3.1 client authentication for the <c>/oauth2/*</c> endpoints.
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

    public OAuthClientAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        GatewayValidationService gatewayValidationService)
        : base(options, logger, encoder)
    {
        _gatewayValidationService = gatewayValidationService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
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
    /// </summary>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = $"Basic realm=\"{OAuthClientAuthenticationDefaults.Realm}\", charset=\"UTF-8\"";
        await Response.WriteAsJsonAsync(new Dictionary<string, string>
        {
            ["error"] = Domain.Validators.OAuthErrorCodes.InvalidClient,
            ["error_description"] = "Client authentication failed."
        });
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
