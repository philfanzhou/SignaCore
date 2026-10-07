using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// Extension point — response format. Owns the bodies and status codes of the consumer-facing
/// failure and session-status answers. The package defines the protocol outcomes; this writer
/// defines their presentation.
/// </summary>
public interface ISignaCoreHostedLoginResponseWriter
{
    /// <summary>
    /// Presents the sign-in surface's optional-login degradation: the host started with
    /// <see cref="SignaCoreHostedLoginOptions.AllowUnconfiguredStartup"/> and the protocol
    /// options left blank, so no sign-in can start. Default: <c>503</c> with the JSON body
    /// <c>{"outcome":"sign_in_unavailable"}</c> and <c>no-store</c>. A challenge redirected here
    /// surfaces the same fixed answer; the mode ends only when the host is configured and
    /// restarted.
    /// </summary>
    Task WriteSignInUnavailableAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        return context.Response.WriteAsync("""{"outcome":"sign_in_unavailable"}""", cancellationToken);
    }

    /// <summary>
    /// Answers a failed sign-in or start request. The default redirects to the package's fixed
    /// failure page under the mapped prefix with the bounded <c>reason</c> as its only query
    /// parameter.
    /// </summary>
    /// <param name="context">The request the failure belongs to.</param>
    /// <param name="reason">The closed reason; the only failure detail that may reach the browser.</param>
    /// <param name="cancellationToken">Propagates the caller's cancellation.</param>
    Task WriteSignInFailureAsync(
        HttpContext context,
        SignaCoreSignInReason reason,
        CancellationToken cancellationToken);

    /// <summary>
    /// Renders the fixed failure page itself, addressed by its bounded reason parameter. The
    /// default is a small static English page.
    /// </summary>
    Task WriteFailurePageAsync(
        HttpContext context,
        SignaCoreSignInReason? reason,
        CancellationToken cancellationToken);

    /// <summary>
    /// Answers the session-status endpoint. The default is a fixed JSON body that carries the
    /// status fields and no token.
    /// </summary>
    Task WriteSessionStatusAsync(
        HttpContext context,
        SignaCoreSessionStatus status,
        CancellationToken cancellationToken);
}

/// <summary>
/// The default presentation: a redirect to the fixed failure page for failures, a static English
/// failure page, and a fixed JSON session body. None of the answers varies with any secret, code,
/// or query string of the underlying flow.
/// </summary>
public sealed class SignaCoreDefaultResponseWriter : ISignaCoreHostedLoginResponseWriter
{
    private SignaCoreDefaultResponseWriter()
    {
    }

    /// <summary>The stateless instance every default configuration shares.</summary>
    public static SignaCoreDefaultResponseWriter Instance { get; } = new();

    /// <inheritdoc />
    public Task WriteSignInFailureAsync(
        HttpContext context,
        SignaCoreSignInReason reason,
        CancellationToken cancellationToken)
    {
        var prefix = context.RequestServices
            .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<SignaCoreHostedLoginOptions>>()
            .CurrentValue.Prefix ?? string.Empty;
        context.Response.Redirect($"{prefix}/{SignaCoreHostedLoginDefaults.FailurePathSegment}?reason={ReasonText(reason)}");
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task WriteFailurePageAsync(
        HttpContext context,
        SignaCoreSignInReason? reason,
        CancellationToken cancellationToken)
    {
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        return context.Response.WriteAsync(
            $"""
            <!doctype html>
            <html lang="en">
            <head><title>Sign-in could not complete</title></head>
            <body>
            <h1>Sign-in could not complete</h1>
            <p>{Description(reason)}</p>
            <p><a href="/">Back</a></p>
            </body>
            </html>
            """,
            cancellationToken);
    }

    /// <inheritdoc />
    public Task WriteSessionStatusAsync(
        HttpContext context,
        SignaCoreSessionStatus status,
        CancellationToken cancellationToken)
    {
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        return context.Response.WriteAsync(
            JsonSerializer.Serialize(status, SignaCoreClientJsonContext.Default.SignaCoreSessionStatus),
            cancellationToken);
    }

    internal static string ReasonText(SignaCoreSignInReason reason) => reason switch
    {
        SignaCoreSignInReason.AuthorityUnreachable => "authority_unreachable",
        SignaCoreSignInReason.InvalidReturnUrl => "invalid_return_url",
        SignaCoreSignInReason.InvalidResponse => "invalid_response",
        SignaCoreSignInReason.AccessDenied => "access_denied",
        SignaCoreSignInReason.StateMismatch => "state_mismatch",
        SignaCoreSignInReason.IssuerMismatch => "issuer_mismatch",
        SignaCoreSignInReason.TokenExchangeFailed => "token_exchange_failed",
        SignaCoreSignInReason.InvalidToken => "invalid_token",
        SignaCoreSignInReason.SessionStoreFull => "session_store_full",
        SignaCoreSignInReason.RequiresReauthentication => "requires_reauthentication",
        _ => "invalid_response"
    };

    private static string Description(SignaCoreSignInReason? reason) => reason switch
    {
        SignaCoreSignInReason.AuthorityUnreachable =>
            "The sign-in server is unreachable or its discovery document is invalid.",
        SignaCoreSignInReason.InvalidReturnUrl =>
            "The return address was not a local path.",
        SignaCoreSignInReason.InvalidResponse =>
            "The sign-in response was not usable.",
        SignaCoreSignInReason.AccessDenied =>
            "Access was denied.",
        SignaCoreSignInReason.StateMismatch =>
            "The sign-in response did not match the pending sign-in.",
        SignaCoreSignInReason.IssuerMismatch =>
            "The sign-in response did not come from the expected sign-in server.",
        SignaCoreSignInReason.TokenExchangeFailed =>
            "The sign-in code could not be exchanged.",
        SignaCoreSignInReason.InvalidToken =>
            "The sign-in response failed validation.",
        SignaCoreSignInReason.SessionStoreFull =>
            "The service cannot accept more sessions right now.",
        _ => "Unknown reason."
    };
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SignaCoreSessionStatus))]
internal sealed partial class SignaCoreClientJsonContext : JsonSerializerContext;
