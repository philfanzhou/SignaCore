using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The protocol core behind the package's logout surface: the antiforgery-token endpoint, the
/// local-session-first logout, and the one-time logout return. Every failure path ends in one
/// bounded outcome; every path propagates the caller's cancellation; and no ID token, client
/// secret, logout handle, state, or cookie value is ever written to a response body or a log
/// entry. The local session is always revoked before the upstream preparation is attempted, an
/// upstream failure never rolls it back and never retries, and one session key is revoked at most
/// once with at most one preparation, enforced by striped per-key gates that serialize concurrent
/// logouts of the same browser session.
/// </summary>
internal sealed class SignaCoreHostedLogoutService(
    IOptionsMonitor<SignaCoreHostedLoginOptions> options,
    IAntiforgery antiforgery,
    SignaCoreDiscoveryClient discoveryClient,
    SignaCoreLogoutClient logoutClient,
    ITicketStore ticketStore,
    LogoutReturnStateStore logoutReturnStateStore,
    TimeProvider timeProvider,
    ILogger<SignaCoreHostedLogoutService> logger)
{
    /// <summary>
    /// A fixed stripe of gates keyed by session-key hash: one session always maps to one gate, so
    /// its revoke-then-prepare sequence is strictly serialized, while unrelated sessions spread
    /// across stripes. The bounded stripe count keeps the gate set from growing with every login.
    /// </summary>
    private static readonly SemaphoreSlim[] LogoutGates =
        Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    internal async Task HandleCsrfAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        // The token is bound to the antiforgery cookie set alongside it; issuing one is a public,
        // unauthenticated read — the protection is the cookie binding, not secrecy of the issuer.
        var tokens = antiforgery.GetAndStoreTokens(context);
        SignaCoreClientLog.CsrfIssued(logger, cancellationToken);
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync(
            """{"token":""" + JsonSerializer.Serialize(tokens.RequestToken) + "}",
            cancellationToken);
    }

    internal async Task HandleLogoutAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var current = options.CurrentValue;

        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            // A missing or wrong token changes nothing: no session is touched and no preparation
            // is attempted. The fixed answer is indistinguishable for both defect shapes.
            SignaCoreClientLog.Logout(logger, SignaCoreClientLog.Outcome.CsrfRejected, cancellationToken);
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsync("""{"outcome":"csrf_rejected"}""", cancellationToken);
            return;
        }

        if (!context.Request.Cookies.TryGetValue(current.SessionCookieName, out var key)
            || string.IsNullOrEmpty(key))
        {
            // No session cookie means there is nothing to revoke locally and no ID token to
            // prepare with: the fixed local-only result.
            await WriteLocalOnlyAsync(context, cancellationToken);
            return;
        }

        // One stripe per session key serializes the revoke-then-prepare sequence, so concurrent
        // logouts of the same session revoke exactly once and prepare exactly once.
        var gate = LogoutGates[Math.Abs(key.GetHashCode()) % LogoutGates.Length];
        await gate.WaitAsync(cancellationToken);
        try
        {
            var ticket = await ticketStore.RetrieveAsync(key, cancellationToken);
            if (ticket is null)
            {
                // Another request already revoked this session (or it expired): local-only, no
                // second preparation.
                await WriteLocalOnlyAsync(context, cancellationToken);
                return;
            }

            // The local session ends first, always: the ticket is removed and the cookie is
            // deleted before any upstream call, and neither is ever restored.
            await ticketStore.RemoveAsync(key, cancellationToken);
            DeleteSessionCookie(context, current.SessionCookieName);

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
                await WriteLocalOnlyAsync(context, cancellationToken);
                return;
            }

            // The return state exists only when the browser will actually be sent back; a full
            // store downgrades the logout to upstream-only (SignaCore's own completion page)
            // rather than failing it.
            var state = NewState();
            var correlationId = logoutReturnStateStore.Create(state);
            var postLogoutRedirectUri = correlationId is null ? null : current.PostLogoutRedirectUri;

            var preparation = await logoutClient.PrepareAsync(
                configuration, ticket.IdToken, postLogoutRedirectUri,
                correlationId is null ? null : state, cancellationToken);
            if (preparation.Failure is not null)
            {
                // Upstream failure, timeout, cancellation, or an unverifiable logout_uri: the
                // local sign-out stands, there is no retry, and the browser is told the fixed
                // local-only result.
                await WriteLocalOnlyAsync(context, cancellationToken);
                return;
            }

            if (correlationId is not null)
            {
                SetLogoutReturnCookie(context, current, correlationId);
            }

            SignaCoreClientLog.Logout(logger, SignaCoreClientLog.Outcome.Prepared, cancellationToken);
            context.Response.Redirect(preparation.LogoutUri);
        }
        finally
        {
            gate.Release();
        }

        static string NewState()
        {
            Span<byte> entropy = stackalloc byte[32];
            RandomNumberGenerator.Fill(entropy);
            return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    internal async Task HandleLogoutReturnAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var current = options.CurrentValue;

        // Single-valued state only; anything duplicated is the fixed invalid answer.
        var stateValues = context.Request.Query["state"];
        var correlationId = context.Request.Cookies[current.LogoutReturnCookieName()];
        var presentedState = stateValues.Count == 1 ? stateValues[0] : null;
        var completed = !string.IsNullOrEmpty(presentedState)
            && !string.IsNullOrEmpty(correlationId)
            && logoutReturnStateStore.Consume(correlationId, presentedState);
        SignaCoreClientLog.LogoutReturn(logger, completed, cancellationToken);

        // The correlation cookie is finished either way, and no request input is ever echoed.
        DeleteLogoutReturnCookie(context, current);
        if (!completed)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsync(
                """
                <!doctype html>
                <html lang="en">
                <head><title>Sign-out could not be confirmed</title></head>
                <body>
                <h1>Sign-out could not be confirmed</h1>
                <p>The sign-out result could not be matched. Sign in again if you were trying to use the application.</p>
                <p><a href="/">Back</a></p>
                </body>
                </html>
                """,
                cancellationToken);
            return;
        }

        // The only redirect target: one fixed local path. No request input reaches it.
        context.Response.Redirect(current.PostLogoutReturnPath);
    }

    private async Task WriteLocalOnlyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        SignaCoreClientLog.Logout(logger, SignaCoreClientLog.Outcome.LocalOnly, cancellationToken);
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync("""{"outcome":"local_only"}""", cancellationToken);
    }

    private static void DeleteSessionCookie(HttpContext context, string cookieName) =>
        context.Response.Cookies.Append(cookieName, string.Empty, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Expires = DateTimeOffset.UnixEpoch,
            IsEssential = true
        });

    private void SetLogoutReturnCookie(
        HttpContext context,
        SignaCoreHostedLoginOptions current,
        string correlationId) =>
        context.Response.Cookies.Append(
            current.LogoutReturnCookieName(),
            correlationId,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Path = (current.Prefix ?? string.Empty) + "/" + SignaCoreHostedLoginDefaults.LogoutPathSegment,
                Expires = timeProvider.GetUtcNow() + SignaCoreHostedLoginDefaults.LogoutReturnLifetime,
                IsEssential = true
            });

    private static void DeleteLogoutReturnCookie(HttpContext context, SignaCoreHostedLoginOptions current) =>
        context.Response.Cookies.Append(
            current.LogoutReturnCookieName(),
            string.Empty,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Path = (current.Prefix ?? string.Empty) + "/" + SignaCoreHostedLoginDefaults.LogoutPathSegment,
                Expires = DateTimeOffset.UnixEpoch,
                IsEssential = true
            });
}

/// <summary>Package-internal helpers shared by the logout surface.</summary>
internal static class SignaCoreLogoutCookieExtensions
{
    /// <summary>The logout-return cookie name derives from the configured session-cookie name, so
    /// distinct consumers on one host never read each other's correlation ids.</summary>
    internal static string LogoutReturnCookieName(this SignaCoreHostedLoginOptions options) =>
        options.SessionCookieName + SignaCoreHostedLoginDefaults.LogoutReturnCookieSuffix;
}
