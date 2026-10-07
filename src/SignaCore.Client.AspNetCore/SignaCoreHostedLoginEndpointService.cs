using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The protocol core behind the package's endpoints: the sign-in start, the hardened callback,
/// and the session-status read. Every failure path ends in one bounded reason; every path
/// propagates the caller's cancellation; and no code, state, nonce, verifier, token, secret, or
/// full query string is ever written to a response or a log entry.
/// </summary>
internal sealed class SignaCoreHostedLoginEndpointService(
    IOptionsMonitor<SignaCoreHostedLoginOptions> options,
    SignaCoreDiscoveryClient discoveryClient,
    SignaCoreTokenClient tokenClient,
    SignaCoreIdTokenValidator idTokenValidator,
    SignaCoreAccessTokenValidator accessTokenValidator,
    PendingSignInStore pendingSignInStore,
    ITicketStore ticketStore,
    TimeProvider timeProvider,
    ILogger<SignaCoreHostedLoginEndpointService> logger)
{
    internal async Task HandleStartAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var current = options.CurrentValue;

        // A missing returnUrl defaults to the application root; a present one must be a single
        // local absolute path.
        var returnUrlValues = context.Request.Query["returnUrl"];
        var returnUrl = returnUrlValues.Count == 0 ? "/" : ReadSingleReturnUrl(returnUrlValues);
        if (returnUrl is null)
        {
            await RejectAsync(context, SignaCoreSignInReason.InvalidReturnUrl, cancellationToken);
            return;
        }

        SignaCoreAuthorityConfiguration configuration;
        try
        {
            configuration = await discoveryClient.GetConfigurationAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            await RejectAsync(context, SignaCoreSignInReason.AuthorityUnreachable, cancellationToken);
            return;
        }

        var nonce = NewToken();
        var codeVerifier = NewToken();
        var state = pendingSignInStore.Create(nonce, codeVerifier, returnUrl);
        if (state is null)
        {
            await RejectAsync(context, SignaCoreSignInReason.SessionStoreFull, cancellationToken);
            return;
        }

        SignaCoreClientLog.SignInStarted(logger, cancellationToken);
        var codeChallenge = Convert.ToBase64String(
                SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier)))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        context.Response.Redirect(QueryStringHelpers.BuildAuthorizationRequestUrl(
            configuration.AuthorizationEndpoint,
            current.ClientId!,
            current.RedirectUri!,
            current.Scope,
            state,
            nonce,
            codeChallenge));

        static string NewToken()
        {
            Span<byte> entropy = stackalloc byte[32];
            RandomNumberGenerator.Fill(entropy);
            return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    internal async Task HandleCallbackAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var current = options.CurrentValue;
        var query = context.Request.Query;

        // Only single-valued state, iss, code, and error are ever read; anything duplicated is
        // rejected before one byte of the handshake state is touched.
        foreach (var member in new[] { "state", "iss", "code", "error" })
        {
            if (query[member].Count > 1)
            {
                await RejectAsync(context, SignaCoreSignInReason.InvalidResponse, cancellationToken);
                return;
            }
        }

        var state = query["state"].ToString();
        var iss = query["iss"].ToString();
        var code = query["code"].ToString();
        var error = query["error"].ToString();
        if (string.IsNullOrEmpty(state))
        {
            await RejectAsync(context, SignaCoreSignInReason.InvalidResponse, cancellationToken);
            return;
        }

        // The error shape (the user's cancel, or a request error) carries state and iss but no
        // code; it is classified before the code's presence is required.
        if (!string.IsNullOrEmpty(error))
        {
            await RejectAsync(
                context,
                error == "access_denied"
                    ? SignaCoreSignInReason.AccessDenied
                    : SignaCoreSignInReason.InvalidResponse,
                cancellationToken);
            return;
        }

        if (string.IsNullOrEmpty(code))
        {
            await RejectAsync(context, SignaCoreSignInReason.InvalidResponse, cancellationToken);
            return;
        }

        SignaCoreAuthorityConfiguration configuration;
        try
        {
            configuration = await discoveryClient.GetConfigurationAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            await RejectAsync(context, SignaCoreSignInReason.AuthorityUnreachable, cancellationToken);
            return;
        }

        // RFC 9207: a missing issuer parameter is an unusable response; a present one must equal
        // the Discovery issuer.
        if (string.IsNullOrEmpty(iss))
        {
            pendingSignInStore.Consume(state);
            await RejectAsync(context, SignaCoreSignInReason.InvalidResponse, cancellationToken);
            return;
        }

        if (!string.Equals(iss, configuration.Issuer, StringComparison.Ordinal))
        {
            // The state is consumed by any callback that presents it, so this attempt cannot be
            // retried with a corrected iss against the same pending sign-in.
            pendingSignInStore.Consume(state);
            await RejectAsync(context, SignaCoreSignInReason.IssuerMismatch, cancellationToken);
            return;
        }

        // The state is consumed exactly once, whatever happens next.
        var pending = pendingSignInStore.Consume(state);
        if (pending is null)
        {
            await RejectAsync(context, SignaCoreSignInReason.StateMismatch, cancellationToken);
            return;
        }

        var exchange = await tokenClient.RedeemCodeAsync(
            configuration, code, pending.CodeVerifier, cancellationToken);
        if (exchange.Failure is { } failure)
        {
            await RejectAsync(
                context,
                failure switch
                {
                    SignaCoreTokenExchangeFailure.Unreachable => SignaCoreSignInReason.AuthorityUnreachable,
                    SignaCoreTokenExchangeFailure.Rejected => SignaCoreSignInReason.TokenExchangeFailed,
                    _ => SignaCoreSignInReason.InvalidToken
                },
                cancellationToken);
            return;
        }

        var exchangedAt = timeProvider.GetUtcNow();
        var identity = await idTokenValidator.ValidateAsync(
            configuration, exchange.IdToken, pending.Nonce, cancellationToken);
        if (identity is null)
        {
            await RejectAsync(context, SignaCoreSignInReason.InvalidToken, cancellationToken);
            return;
        }

        var now = timeProvider.GetUtcNow();
        // The session never outlives the access token.
        var expiresAt = now.AddSeconds(exchange.ExpiresIn);
        if (current.PreSignInAuthorizationDecision is { } decision)
        {
            var access = await accessTokenValidator.ValidateAsync(
                configuration, exchange.AccessToken, cancellationToken);
            if (access is null
                || !string.Equals(access.Issuer, identity.Issuer, StringComparison.Ordinal)
                || !string.Equals(access.Subject, identity.Subject, StringComparison.Ordinal))
            {
                await RejectAsync(context, SignaCoreSignInReason.InvalidToken, cancellationToken);
                return;
            }

            var authorizationContext = new SignaCorePreSignInAuthorizationContext(
                access.Principal, identity.Principal, access.Issuer, access.Subject);
            if (!await AuthorizeSignInAsync(decision, authorizationContext,
                current.PreSignInAuthorizationTimeout, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await RejectAsync(context, SignaCoreSignInReason.AccessDenied, cancellationToken);
                return;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (access.ExpiresUtc <= timeProvider.GetUtcNow())
            {
                await RejectAsync(context, SignaCoreSignInReason.InvalidToken, cancellationToken);
                return;
            }

            now = exchangedAt;
            expiresAt = exchangedAt.AddSeconds(exchange.ExpiresIn);
            if (access.ExpiresUtc < expiresAt) expiresAt = access.ExpiresUtc;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            identity.Principal.Claims, "SignaCoreHostedLogin", nameType: "name", roleType: "role"));
        var ticket = new SignaCoreSessionTicket(
            principal, now, expiresAt, exchange.AccessToken, exchange.IdToken);
        // A fresh sign-in replaces the session this browser held before, atomically: the store
        // takes the new ticket and revokes the old key in one call, so a re-login ends the
        // previous session the moment the new one exists. No previous cookie degrades to a plain
        // store; a full store refuses the whole replacement and keeps the old session.
        context.Request.Cookies.TryGetValue(current.SessionCookieName, out var previousSessionKey);
        var key = await ticketStore.ReplaceAsync(
            string.IsNullOrEmpty(previousSessionKey) ? null : previousSessionKey,
            ticket,
            cancellationToken);
        if (key is null)
        {
            await RejectAsync(context, SignaCoreSignInReason.SessionStoreFull, cancellationToken);
            return;
        }

        context.Response.Cookies.Append(
            current.SessionCookieName,
            key,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Expires = expiresAt,
                IsEssential = true
            });
        SignaCoreClientLog.SignInSucceeded(logger, cancellationToken);
        context.Response.Redirect(pending.ReturnUrl);
    }

    private async Task<bool> AuthorizeSignInAsync(
        ISignaCorePreSignInAuthorizationDecision decision,
        SignaCorePreSignInAuthorizationContext context, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<SignaCoreAuthorizationDecisionResult>? task = null;
        try
        {
            var started = timeProvider.GetTimestamp();
            task = decision.DecideAsync(context, linked.Token).AsTask();
            var remaining = timeout - timeProvider.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) throw new TimeoutException();
            var result = await task.WaitAsync(remaining, timeProvider, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return result == SignaCoreAuthorizationDecisionResult.Allowed;
        }
        catch (Exception)
        {
            // Observe a non-cooperative task's late failure without giving it a sign-in path.
            if (task is not null)
                _ = task.ContinueWith(static completed => { _ = completed.Exception; },
                    CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted
                    | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            try { linked.Cancel(); } catch (Exception) { /* Consumer cancellation callbacks. */ }
            cancellationToken.ThrowIfCancellationRequested();
            return false;
        }
    }

    internal async Task HandleSessionAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var current = options.CurrentValue;
        var status = await ReadSessionStatusAsync(context, current, cancellationToken);
        SignaCoreClientLog.SessionStatus(logger, status.Authenticated, cancellationToken);
        await current.ResponseWriter.WriteSessionStatusAsync(context, status, cancellationToken);
    }

    internal async Task HandleFailurePageAsync(HttpContext context)
    {
        var reason = ParseReason(context.Request.Query["reason"].ToString());
        await options.CurrentValue.ResponseWriter.WriteFailurePageAsync(context, reason, context.RequestAborted);
    }

    private async Task<SignaCoreSessionStatus> ReadSessionStatusAsync(
        HttpContext context,
        SignaCoreHostedLoginOptions current,
        CancellationToken cancellationToken)
    {
        if (!context.Request.Cookies.TryGetValue(current.SessionCookieName, out var key)
            || string.IsNullOrEmpty(key))
        {
            return SignaCoreSessionStatus.Expired;
        }

        var ticket = await ticketStore.RetrieveAsync(key, cancellationToken);
        if (ticket is null)
        {
            // The fixed answer of an expired or unknown session: re-authentication is the only
            // way forward, and the package never refreshes silently.
            return SignaCoreSessionStatus.Expired;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var decision = await current.AuthorizationDecision.DecideAsync(ticket.Principal, cancellationToken);
        var displayName = ticket.Principal.FindFirst("name")?.Value;
        return SignaCoreSessionStatus.AuthenticatedSession(displayName, decision);
    }

    private async Task RejectAsync(
        HttpContext context,
        SignaCoreSignInReason reason,
        CancellationToken cancellationToken)
    {
        SignaCoreClientLog.SignInRejected(logger, reason, cancellationToken);
        await options.CurrentValue.ResponseWriter.WriteSignInFailureAsync(context, reason, cancellationToken);
    }

    /// <summary>
    /// The <c>returnUrl</c> must be one value and a local absolute path: it starts with exactly
    /// one slash, so no scheme, no protocol-relative origin, and no other host can be smuggled in.
    /// </summary>
    private static string? ReadSingleReturnUrl(StringValues values) =>
        values.Count != 1 ? null : AsLocalPath(values.ToString());

    internal static string? AsLocalPath(string? value)
    {
        if (string.IsNullOrEmpty(value)
            || value[0] != '/'
            || (value.Length > 1 && (value[1] == '/' || value[1] == '\\')))
        {
            return null;
        }

        return value;
    }

    private static SignaCoreSignInReason? ParseReason(string? value) => value switch
    {
        "authority_unreachable" => SignaCoreSignInReason.AuthorityUnreachable,
        "invalid_return_url" => SignaCoreSignInReason.InvalidReturnUrl,
        "invalid_response" => SignaCoreSignInReason.InvalidResponse,
        "access_denied" => SignaCoreSignInReason.AccessDenied,
        "state_mismatch" => SignaCoreSignInReason.StateMismatch,
        "issuer_mismatch" => SignaCoreSignInReason.IssuerMismatch,
        "token_exchange_failed" => SignaCoreSignInReason.TokenExchangeFailed,
        "invalid_token" => SignaCoreSignInReason.InvalidToken,
        "session_store_full" => SignaCoreSignInReason.SessionStoreFull,
        "requires_reauthentication" => SignaCoreSignInReason.RequiresReauthentication,
        _ => null
    };
}

/// <summary>Builds the authorization request URL with exactly the contract's fields, in a fixed
/// order, and nothing else — no <c>prompt</c>, <c>max_age</c>, <c>acr_values</c>,
/// <c>response_mode</c>, <c>request</c>, <c>request_uri</c>, or <c>registration</c>.</summary>
internal static class QueryStringHelpers
{
    internal static string BuildAuthorizationRequestUrl(
        string authorizationEndpoint,
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string nonce,
        string codeChallenge) =>
        authorizationEndpoint
        + "?response_type=" + Uri.EscapeDataString(SignaCoreHostedLoginDefaults.ResponseType)
        + "&client_id=" + Uri.EscapeDataString(clientId)
        + "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
        + "&scope=" + Uri.EscapeDataString(scope)
        + "&state=" + Uri.EscapeDataString(state)
        + "&nonce=" + Uri.EscapeDataString(nonce)
        + "&code_challenge=" + Uri.EscapeDataString(codeChallenge)
        + "&code_challenge_method=" + Uri.EscapeDataString(SignaCoreHostedLoginDefaults.CodeChallengeMethod);
}
