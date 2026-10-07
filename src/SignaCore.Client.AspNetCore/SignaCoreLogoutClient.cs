using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The outcome of one prepared-logout request: either the browser-ready absolute logout URI, or a
/// closed failure kind. Neither side of the result carries the ID token, the client secret, or the
/// logout handle.
/// </summary>
internal sealed record SignaCoreLogoutPreparationResult
{
    /// <summary>The absolute, same-origin logout URI the browser is sent to. Empty on failure.</summary>
    public required string LogoutUri { get; init; }

    public SignaCoreLogoutFailure? Failure { get; init; }

    internal static SignaCoreLogoutPreparationResult Success(string logoutUri) => new()
    {
        LogoutUri = logoutUri
    };

    internal static SignaCoreLogoutPreparationResult Failed(SignaCoreLogoutFailure failure) => new()
    {
        LogoutUri = string.Empty,
        Failure = failure
    };
}

/// <summary>The closed failure kinds of the preparation step.</summary>
internal enum SignaCoreLogoutFailure
{
    /// <summary>The transport failed (unreachable endpoint, TLS failure, timeout, cancellation).</summary>
    Unreachable,

    /// <summary>The endpoint answered an error status — the request was refused, not lost.</summary>
    Rejected,

    /// <summary>The response was not a usable success: a missing member or an unverifiable,
    /// cross-origin, or malformed <c>logout_uri</c>. The browser is never sent to it.</summary>
    MalformedResponse
}

/// <summary>
/// Prepares one SignaCore logout: a single <c>POST /oauth2/logout/requests</c> with HTTP Basic
/// client authentication — the same exclusive method the token endpoint uses — carrying only the
/// server-held ID token as <c>id_token_hint</c> plus the optional post-logout URI and state. No
/// retry, ever: logout is not idempotent at the authority, so a lost answer must not be replayed
/// blindly. The returned <c>logout_uri</c> is accepted only as a relative path or a same-origin
/// absolute URI whose sole query value is one 43-character base64url <c>logout_handle</c>; every
/// other shape is a closed failure so a hostile or broken authority cannot redirect the browser.
/// The ID token and secret stay in this server-to-server call.
/// </summary>
internal sealed class SignaCoreLogoutClient(
    System.Net.Http.IHttpClientFactory httpClientFactory,
    IOptionsMonitor<SignaCoreHostedLoginOptions> options)
{
    private const string PreparePath = "/oauth2/logout/requests";

    internal async Task<SignaCoreLogoutPreparationResult> PrepareAsync(
        SignaCoreAuthorityConfiguration configuration,
        string idToken,
        string? postLogoutRedirectUri,
        string? state,
        CancellationToken cancellationToken)
    {
        var current = options.CurrentValue;
        // Discovery publishes no logout metadata (AC-10); the preparation endpoint is derived from
        // the verified same-origin token endpoint, so a re-homed authority is still followed.
        var authorityOrigin = new Uri(configuration.TokenEndpoint).GetComponents(
            UriComponents.Scheme | UriComponents.Host | UriComponents.Port, UriFormat.UriEscaped);
        using var client = httpClientFactory.CreateClient(SignaCoreHostedLoginDefaults.HttpClientName);

        var form = new Dictionary<string, string>
        {
            ["id_token_hint"] = idToken
        };
        // A state is only ever sent together with the post-logout URI it will be echoed back to;
        // without a redirect there is nothing to correlate.
        if (!string.IsNullOrEmpty(postLogoutRedirectUri))
        {
            form["post_logout_redirect_uri"] = postLogoutRedirectUri;
            form["state"] = state ?? string.Empty;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, authorityOrigin + PreparePath)
        {
            Content = new FormUrlEncodedContent(form)
        };
        // client_secret_basic — one authentication method, never two, same as the token endpoint.
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(current.ClientId!)}:{Uri.EscapeDataString(current.ClientSecret!)}")));

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller abandoned the request; the cancellation propagates untouched.
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            // An unreachable endpoint, or a timeout without the caller's cancellation: a closed
            // failure, never a retry.
            return SignaCoreLogoutPreparationResult.Failed(SignaCoreLogoutFailure.Unreachable);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                return SignaCoreLogoutPreparationResult.Failed(SignaCoreLogoutFailure.Rejected);
            }

            JsonDocument document;
            try
            {
                // The body is read under the configured byte ceiling and must not repeat a
                // top-level member name; both defect shapes are the same closed failure.
                document = await SignaCoreBoundedJson.ParseAsync(
                    await response.Content.ReadAsStreamAsync(cancellationToken),
                    current.Validation.MaxLogoutResponseBytes,
                    current.Validation.RejectDuplicateJsonMembers,
                    cancellationToken);
            }
            catch (Exception exception) when (exception is JsonException
                or SignaCoreResponseLimitException or HttpRequestException)
            {
                return SignaCoreLogoutPreparationResult.Failed(
                    SignaCoreLogoutFailure.MalformedResponse);
            }

            using (document)
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object
                    || !document.RootElement.TryGetProperty("logout_uri", out var uriElement)
                    || uriElement.ValueKind != JsonValueKind.String
                    || string.IsNullOrEmpty(uriElement.GetString()))
                {
                    return SignaCoreLogoutPreparationResult.Failed(
                        SignaCoreLogoutFailure.MalformedResponse);
                }

                if (!TryResolveLogoutUri(uriElement.GetString()!, authorityOrigin, out var resolved))
                {
                    return SignaCoreLogoutPreparationResult.Failed(
                        SignaCoreLogoutFailure.MalformedResponse);
                }

                return SignaCoreLogoutPreparationResult.Success(resolved);
            }
        }
    }

    /// <summary>
    /// Accepts exactly the contract's <c>logout_uri</c> shapes: a local absolute path (one leading
    /// slash, not protocol-relative) resolved against the authority origin, or an absolute
    /// same-origin URI. The query must be exactly one <c>logout_handle</c> of 43 base64url
    /// characters; no fragment is allowed. Anything else — a different origin, extra query fields,
    /// a wrong handle shape — is rejected.
    /// </summary>
    internal static bool TryResolveLogoutUri(
        string logoutUri,
        string authorityOrigin,
        out string resolved)
    {
        resolved = string.Empty;
        if (string.IsNullOrEmpty(logoutUri)
            || logoutUri.Length > 2048
            || logoutUri.Contains('\r') || logoutUri.Contains('\n'))
        {
            return false;
        }

        Uri absolute;
        if (logoutUri[0] == '/')
        {
            // Protocol-relative and backslash forms are origins in disguise, not local paths.
            if (logoutUri.Length > 1 && (logoutUri[1] == '/' || logoutUri[1] == '\\'))
            {
                return false;
            }

            absolute = new Uri(new Uri(authorityOrigin), logoutUri);
        }
        else if (Uri.TryCreate(logoutUri, UriKind.Absolute, out var parsed))
        {
            var parsedOrigin = parsed.GetComponents(
                UriComponents.Scheme | UriComponents.Host | UriComponents.Port, UriFormat.UriEscaped);
            if (!string.Equals(parsedOrigin, authorityOrigin, StringComparison.Ordinal))
            {
                return false;
            }

            absolute = parsed;
        }
        else
        {
            return false;
        }

        if (absolute.UserInfo.Length > 0 || absolute.Fragment.Length > 0)
        {
            return false;
        }

        var query = absolute.Query;
        if (query.Length == 0)
        {
            return false;
        }

        var fields = query.TrimStart('?').Split('&');
        if (fields.Length != 1)
        {
            return false;
        }

        var pair = fields[0].Split('=', 2);
        if (pair.Length != 2
            || pair[0] != "logout_handle"
            || pair[1].Length != 43
            || !pair[1].All(character => character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z')
                or (>= '0' and <= '9') or '-' or '_'))
        {
            return false;
        }

        resolved = absolute.AbsoluteUri;
        return true;
    }
}
