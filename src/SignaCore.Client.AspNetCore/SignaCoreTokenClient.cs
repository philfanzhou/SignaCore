using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The outcome of one code redemption: either the validated token response, or a closed failure
/// kind. Neither side of the result carries the code, the client secret, or any token.
/// </summary>
internal sealed record SignaCoreTokenExchangeResult
{
    public required string AccessToken { get; init; }

    public required string IdToken { get; init; }

    /// <summary>The <c>expires_in</c> seconds; always positive on the success side.</summary>
    public required int ExpiresIn { get; init; }

    public SignaCoreTokenExchangeFailure? Failure { get; init; }

    internal static SignaCoreTokenExchangeResult Success(
        string accessToken, string idToken, int expiresIn) => new()
    {
        AccessToken = accessToken,
        IdToken = idToken,
        ExpiresIn = expiresIn
    };

    internal static SignaCoreTokenExchangeResult Failed(SignaCoreTokenExchangeFailure failure) => new()
    {
        AccessToken = string.Empty,
        IdToken = string.Empty,
        ExpiresIn = 0,
        Failure = failure
    };
}

/// <summary>The closed failure kinds of the redemption step.</summary>
internal enum SignaCoreTokenExchangeFailure
{
    /// <summary>The transport failed (unreachable endpoint, TLS failure, timeout).</summary>
    Unreachable,

    /// <summary>The endpoint answered an error status or an <c>error</c> payload — including the
    /// <c>invalid_grant</c> of a replayed code.</summary>
    Rejected,

    /// <summary>The response was not a usable success: a member missing, a wrong
    /// <c>token_type</c>, or a non-positive <c>expires_in</c>.</summary>
    MalformedResponse
}

/// <summary>
/// Redeems a one-time authorization code exactly once: one POST with HTTP Basic client
/// authentication, no retry, no <c>scope</c>, the same <c>redirect_uri</c>, and the PKCE
/// verifier. The success side of the answer must carry an access token, an ID token,
/// <c>token_type=Bearer</c>, and a positive <c>expires_in</c>; anything else is a closed failure.
/// </summary>
internal sealed class SignaCoreTokenClient(
    System.Net.Http.IHttpClientFactory httpClientFactory,
    IOptionsMonitor<SignaCoreHostedLoginOptions> options)
{
    internal async Task<SignaCoreTokenExchangeResult> RedeemCodeAsync(
        SignaCoreAuthorityConfiguration configuration,
        string code,
        string codeVerifier,
        CancellationToken cancellationToken)
    {
        var current = options.CurrentValue;
        using var client = httpClientFactory.CreateClient(SignaCoreHostedLoginDefaults.HttpClientName);

        using var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = current.RedirectUri!,
                ["code_verifier"] = codeVerifier
            })
        };
        // client_secret_basic — one authentication method, never two.
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
            // An unreachable endpoint, or a timeout (which surfaces without the caller's
            // cancellation): a closed failure, never a retry.
            return SignaCoreTokenExchangeResult.Failed(SignaCoreTokenExchangeFailure.Unreachable);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                return SignaCoreTokenExchangeResult.Failed(SignaCoreTokenExchangeFailure.Rejected);
            }

            JsonDocument? document;
            try
            {
                document = await response.Content.ReadFromJsonAsync<JsonDocument>(
                    cancellationToken);
            }
            catch (JsonException)
            {
                return SignaCoreTokenExchangeResult.Failed(SignaCoreTokenExchangeFailure.MalformedResponse);
            }

            using (document)
            {
                if (document is null)
                {
                    return SignaCoreTokenExchangeResult.Failed(
                        SignaCoreTokenExchangeFailure.MalformedResponse);
                }

                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return SignaCoreTokenExchangeResult.Failed(
                        SignaCoreTokenExchangeFailure.MalformedResponse);
                }

                if (root.TryGetProperty("error", out _))
                {
                    return SignaCoreTokenExchangeResult.Failed(SignaCoreTokenExchangeFailure.Rejected);
                }

                if (!TryReadString(root, "access_token", out var accessToken)
                    || !TryReadString(root, "id_token", out var idToken))
                {
                    return SignaCoreTokenExchangeResult.Failed(
                        SignaCoreTokenExchangeFailure.MalformedResponse);
                }

                if (!TryReadString(root, "token_type", out var tokenType)
                    || !string.Equals(tokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
                {
                    return SignaCoreTokenExchangeResult.Failed(
                        SignaCoreTokenExchangeFailure.MalformedResponse);
                }

                if (!root.TryGetProperty("expires_in", out var expiresInElement)
                    || expiresInElement.ValueKind != JsonValueKind.Number
                    || !expiresInElement.TryGetInt32(out var expiresIn)
                    || expiresIn <= 0)
                {
                    return SignaCoreTokenExchangeResult.Failed(
                        SignaCoreTokenExchangeFailure.MalformedResponse);
                }

                return SignaCoreTokenExchangeResult.Success(accessToken, idToken, expiresIn);
            }
        }
    }

    private static bool TryReadString(JsonElement root, string member, out string value)
    {
        if (root.TryGetProperty(member, out var element)
            && element.ValueKind == JsonValueKind.String)
        {
            var text = element.GetString();
            if (!string.IsNullOrEmpty(text))
            {
                value = text;
                return true;
            }
        }

        value = string.Empty;
        return false;
    }
}
