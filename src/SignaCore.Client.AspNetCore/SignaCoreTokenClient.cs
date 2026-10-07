using System.Net.Http.Headers;
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

            JsonDocument document;
            try
            {
                // The body is read under the configured byte ceiling and must not repeat a
                // top-level member name; both defect shapes are the same closed failure.
                document = await SignaCoreBoundedJson.ParseAsync(
                    await response.Content.ReadAsStreamAsync(cancellationToken),
                    current.Validation.MaxTokenResponseBytes,
                    current.Validation.RejectDuplicateJsonMembers,
                    cancellationToken);
            }
            catch (Exception exception) when (exception is JsonException
                or SignaCoreResponseLimitException or HttpRequestException)
            {
                return SignaCoreTokenExchangeResult.Failed(
                    SignaCoreTokenExchangeFailure.MalformedResponse);
            }

            using (document)
            {
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

                // A present scope echo must be a subset of what the sign-in requested: an
                // authority answering with more than was asked for is a closed failure. An
                // absent member is the contract's optional form and stays accepted.
                if (current.Validation.RequireScopeEchoSubset
                    && root.TryGetProperty("scope", out var scopeElement)
                    && (scopeElement.ValueKind != JsonValueKind.String
                        || !IsScopeEchoSubset(scopeElement.GetString(), current.Scope)))
                {
                    return SignaCoreTokenExchangeResult.Failed(
                        SignaCoreTokenExchangeFailure.MalformedResponse);
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

    /// <summary>Whether every space-separated value of an echoed scope was part of the requested
    /// scope; an empty echo claims nothing beyond the request.</summary>
    private static bool IsScopeEchoSubset(string? echoed, string requested)
    {
        if (string.IsNullOrEmpty(echoed))
        {
            return true;
        }

        requested = requested ?? string.Empty;
        var requestedValues = new HashSet<string>(
            requested.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);
        foreach (var value in echoed.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!requestedValues.Contains(value))
            {
                return false;
            }
        }

        return true;
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
