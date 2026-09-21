using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SignaCore.ReferenceBff;

/// <summary>Outcome of re-checking the signed-in identity against the upstream authority.</summary>
internal enum BffIdentityCheckStatus
{
    /// <summary>
    /// The authority confirmed the session: exactly one string <c>sub</c>, Ordinal-equal to the
    /// subject verified at sign-in. The profile payload is available for <c>/bff/me</c>.
    /// </summary>
    Confirmed,

    /// <summary>
    /// The local session no longer names a valid upstream identity (no stored token, an upstream
    /// 401, or a subject the authority no longer confirms). The session must be torn down.
    /// </summary>
    SessionInvalid,

    /// <summary>
    /// The authority or its answers could not be used (unreachable, missing UserInfo endpoint,
    /// non-401 failure, malformed JSON, or an internal cancellation). The session stays intact.
    /// </summary>
    Unavailable
}

/// <summary>The result of one identity check: the status plus what a confirmed check proved.</summary>
internal sealed record BffIdentityCheckResult(
    BffIdentityCheckStatus Status,
    string? VerifiedIssuer = null,
    string? VerifiedSubject = null,
    string? ProfilePayload = null,
    string? ProfileContentType = null)
{
    public static readonly BffIdentityCheckResult SessionInvalid = new(BffIdentityCheckStatus.SessionInvalid);
    public static readonly BffIdentityCheckResult Unavailable = new(BffIdentityCheckStatus.Unavailable);
}

/// <summary>
/// The typed identity check behind every identity-sensitive surface: reads the server-side ticket,
/// resolves UserInfo from Discovery, presents the stored access token once, and requires the
/// successful JSON object to carry exactly one string <c>sub</c> Ordinal-equal to the subject
/// verified at sign-in. One call performs at most one UserInfo round trip; caller cancellation
/// propagates, and every other failure stays inside the typed result — no upstream detail, token,
/// or payload fragment is ever surfaced by this service.
/// </summary>
internal sealed class BffIdentityCheckService(
    IHttpClientFactory httpClientFactory,
    IOptionsMonitor<OpenIdConnectOptions> oidcOptions)
{
    /// <summary>The named client that carries the Bearer header on the server-to-server leg.</summary>
    public const string UserInfoClientName = "signacore";

    public async Task<BffIdentityCheckResult> CheckAsync(HttpContext http, CancellationToken cancellationToken)
    {
        var result = await CheckCoreAsync(http, cancellationToken);
        http.RequestServices.GetRequiredService<BffOperationLog>()
            .Record(BffLogOperation.UserInfo, result.Status, cancellationToken);
        return result;
    }

    private async Task<BffIdentityCheckResult> CheckCoreAsync(HttpContext http, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var authentication = await http.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authentication.Succeeded || authentication.Properties is null)
        {
            return BffIdentityCheckResult.SessionInvalid;
        }

        // A ticket from before the verified-identity capture answers nothing: it cannot prove
        // which identity the authority signed in, and no identity is ever inferred for it.
        var verified = ReferenceBffVerifiedIdentity.Read(authentication.Properties);
        if (verified is null)
        {
            return BffIdentityCheckResult.SessionInvalid;
        }

        var accessToken = authentication.Properties.GetTokenValue("access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            return BffIdentityCheckResult.SessionInvalid;
        }

        var userInfoEndpoint = await ResolveUserInfoEndpointAsync(cancellationToken);
        // The caller's decision outranks any classification of the completed boundary —
        // including "the configuration carries no UserInfo endpoint": a caller who abandoned
        // the request never receives an unavailable verdict for it.
        cancellationToken.ThrowIfCancellationRequested();
        if (userInfoEndpoint is null)
        {
            return BffIdentityCheckResult.Unavailable;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        HttpResponseMessage response;
        try
        {
            response = await httpClientFactory.CreateClient(UserInfoClientName)
                .SendAsync(request, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // An internal timeout while the caller still waits: bounded unavailable, not a
            // session verdict.
            return BffIdentityCheckResult.Unavailable;
        }
        catch (HttpRequestException)
        {
            return BffIdentityCheckResult.Unavailable;
        }

        using (response)
        {
            // The caller's decision outranks any classification of the completed call.
            cancellationToken.ThrowIfCancellationRequested();

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return BffIdentityCheckResult.SessionInvalid;
            }

            if (!response.IsSuccessStatusCode)
            {
                return BffIdentityCheckResult.Unavailable;
            }

            string payload;
            string contentType;
            try
            {
                payload = await response.Content.ReadAsStringAsync(cancellationToken);
                contentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                return BffIdentityCheckResult.Unavailable;
            }

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var document = JsonDocument.Parse(payload);
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    return BffIdentityCheckResult.Unavailable;
                }

                var upstreamSubject = ReadSingleSubject(document.RootElement);
                if (upstreamSubject is null
                    || !string.Equals(upstreamSubject, verified.Value.Subject, StringComparison.Ordinal))
                {
                    // The authority no longer confirms the identity this session was built on.
                    return BffIdentityCheckResult.SessionInvalid;
                }

                return new BffIdentityCheckResult(
                    BffIdentityCheckStatus.Confirmed,
                    verified.Value.Issuer,
                    verified.Value.Subject,
                    payload,
                    contentType);
            }
            catch (JsonException)
            {
                return BffIdentityCheckResult.Unavailable;
            }
        }
    }

    private async Task<string?> ResolveUserInfoEndpointAsync(CancellationToken cancellationToken)
    {
        try
        {
            var configuration = await oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme)
                .ConfigurationManager!.GetConfigurationAsync(cancellationToken);
            var endpoint = configuration.UserInfoEndpoint;
            return string.IsNullOrEmpty(endpoint) ? null : endpoint;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // An internal cancellation while the caller still waits: bounded unavailable — but
            // the caller is re-observed first, so a cancellation landing in the same breath as
            // the throw still wins the classification.
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
    }

    /// <summary>
    /// Reads the single string <c>sub</c> member. Zero members, more than one, any empty value,
    /// or any non-string value answers null: there is no single confirmed subject.
    /// </summary>
    private static string? ReadSingleSubject(JsonElement objectElement)
    {
        string? subject = null;
        var members = 0;
        foreach (var property in objectElement.EnumerateObject())
        {
            if (!string.Equals(property.Name, "sub", StringComparison.Ordinal))
            {
                continue;
            }

            members++;
            if (property.Value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(property.Value.GetString()))
            {
                return null;
            }

            subject = property.Value.GetString();
        }

        return members == 1 ? subject : null;
    }
}
