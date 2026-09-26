using System.Text;
using System.Text.Json;
using Microsoft.Net.Http.Headers;
using ServiceMantle.AspNetCore.ManagementApi.Entries;
using ServiceMantle.AspNetCore.RateLimiting;
using ServiceMantle.Management;

namespace SignaCore.Host.Management;

/// <summary>
/// The explicit management bearer session entries: <c>POST /api/admin/session/bearer/login</c>
/// issues a short-lived management bearer for the bootstrap administrator, and
/// <c>POST /api/admin/session/bearer/logout</c> revokes the bearer that authenticated the request.
/// </summary>
/// <remarks>
/// <para>
/// The login reuses the shared management login chain unchanged — the scoped credential accessor,
/// <see cref="SignaCoreManagementIdentityProvider"/>, the same password validator, bootstrap
/// administrator restriction, and login attempt/audit recording — and calls
/// <see cref="ManagementBearerSessionService.IssueAsync"/> only after an authenticated result. It is
/// anonymous and reads no existing principal, so an accompanying <c>Authorization</c> header or
/// management cookie never changes its outcome, and it signs nothing in. It shares the setup rate
/// limit budget of the shared cookie login and its 10 second login budget.
/// </para>
/// <para>
/// The logout authenticates through the management bearer scheme alone (the
/// <see cref="ManagementBearerAuthenticationDefaults.Policy"/> policy), so a cookie-only request gets
/// that scheme's fixed 401 instead of being authenticated by the cookie.
/// </para>
/// <para>
/// Neither entry writes the password or the bearer anywhere but the success response body; every
/// failure is a fixed JSON body with <c>Cache-Control: no-store</c> that echoes no input.
/// </para>
/// </remarks>
internal static class ManagementBearerSessionEndpoints
{
    internal const string LoginPath = "/api/admin/session/bearer/login";
    internal const string LogoutPath = "/api/admin/session/bearer/logout";

    /// <summary>The raw request body limit, counted in bytes before decoding.</summary>
    internal const int MaximumBodyLength = 64 * 1024;

    /// <summary>The login budget, the same as the shared cookie login's default.</summary>
    internal static readonly TimeSpan LoginBudget = TimeSpan.FromSeconds(10);

    private const string BearerPrefix = "Bearer ";
    private const string InvalidRequestBody = """{"errorCode":"management.request.invalid"}""";
    private const string UnauthenticatedBody = """{"errorCode":"management.session.unauthenticated"}""";
    private const string UnavailableBody = """{"errorCode":"management.session.unavailable"}""";
    private const string BearerUnauthenticatedBody = """{"errorCode":"management.bearer.unauthenticated"}""";
    private const string BearerUnavailableBody = """{"errorCode":"management.bearer.unavailable"}""";

    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost(LoginPath, LoginAsync)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitingDefaults.SetupPolicyName);

        app.MapPost(LogoutPath, LogoutAsync)
            .RequireAuthorization(ManagementBearerAuthenticationDefaults.Policy)
            .RequireRateLimiting(RateLimitingDefaults.ManagementPolicyName);
    }

    private static async Task LoginAsync(HttpContext context)
    {
        var requestAborted = context.RequestAborted;
        if (!HasUnsafeRequestHeader(context.Request) ||
            context.Request.QueryString.HasValue ||
            context.Request.Headers.ContainsKey(HeaderNames.ContentEncoding) ||
            !IsJsonContentType(context.Request.ContentType) ||
            context.Request.ContentLength > MaximumBodyLength)
        {
            await WriteAsync(context, StatusCodes.Status400BadRequest, InvalidRequestBody);
            return;
        }

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(requestAborted);
        budget.CancelAfter(LoginBudget);
        try
        {
            var body = await ReadBoundedBodyAsync(context.Request, budget.Token);
            if (body is null || !TryParseCredentials(body, out var username, out var password))
            {
                await WriteAsync(context, StatusCodes.Status400BadRequest, InvalidRequestBody);
                return;
            }

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                await WriteAsync(context, StatusCodes.Status401Unauthorized, UnauthenticatedBody);
                return;
            }

            var services = context.RequestServices;
            services.GetRequiredService<ManagementCredentialAccessor>().Set(username.Trim(), password);
            var identity = await ManagementIdentityProviderInvoker.InvokeAsync(
                services.GetRequiredService<IManagementIdentityProvider>(),
                budget.Token);
            if (identity.Status == ManagementIdentityStatus.Unauthenticated)
            {
                await WriteAsync(context, StatusCodes.Status401Unauthorized, UnauthenticatedBody);
                return;
            }

            if (identity.Status != ManagementIdentityStatus.Authenticated ||
                !Guid.TryParse(identity.Identity?.OperatorId, out var accountId))
            {
                await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, UnavailableBody);
                return;
            }

            var issued = await services.GetRequiredService<ManagementBearerSessionService>()
                .IssueAsync(accountId, budget.Token);
            if (issued.Status != ManagementBearerIssueStatus.Issued)
            {
                await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, UnavailableBody);
                return;
            }

            // A caller that went away after the commit never receives the credential; the row
            // expires on its own.
            requestAborted.ThrowIfCancellationRequested();
            await WriteAsync(
                context,
                StatusCodes.Status200OK,
                JsonSerializer.Serialize(new
                {
                    tokenType = "Bearer",
                    accessToken = issued.Token,
                    expiresAtUtc = issued.ExpiresAtUtc
                }));
        }
        catch (OperationCanceledException) when (requestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (budget.IsCancellationRequested)
        {
            await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, UnavailableBody);
        }
    }

    private static async Task LogoutAsync(HttpContext context)
    {
        if (!HasUnsafeRequestHeader(context.Request))
        {
            await WriteAsync(context, StatusCodes.Status400BadRequest, InvalidRequestBody);
            return;
        }

        // The bearer scheme already accepted exactly one "Bearer <token>" value; the same raw value
        // is revoked, never a credential from the query string or the body.
        var authorization = context.Request.Headers.Authorization;
        var token = authorization.Count == 1 &&
                    authorization[0] is { } value &&
                    value.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase)
            ? value[BearerPrefix.Length..]
            : null;

        var result = await context.RequestServices.GetRequiredService<ManagementBearerSessionService>()
            .RevokeAsync(token, context.RequestAborted);
        switch (result)
        {
            case ManagementBearerRevocationResult.Revoked:
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                context.Response.Headers.CacheControl = "no-store";
                return;
            case ManagementBearerRevocationResult.Unavailable:
                await WriteAsync(context, StatusCodes.Status503ServiceUnavailable, BearerUnavailableBody);
                return;
            default:
                // Revoked or expired between authentication and revocation.
                context.Response.Headers.WWWAuthenticate = "Bearer";
                await WriteAsync(context, StatusCodes.Status401Unauthorized, BearerUnauthenticatedBody);
                return;
        }
    }

    private static bool HasUnsafeRequestHeader(HttpRequest request)
    {
        var guard = request.Headers[ManagementEntryDefaults.UnsafeRequestHeaderName];
        return guard.Count == 1 && string.Equals(
            guard[0],
            ManagementEntryDefaults.UnsafeRequestHeaderValue,
            StringComparison.Ordinal);
    }

    private static bool IsJsonContentType(string? contentType)
    {
        if (!MediaTypeHeaderValue.TryParse(contentType, out var parsed) ||
            !string.Equals(parsed.MediaType.Value, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var charset = parsed.Charset;
        return !charset.HasValue ||
               string.Equals(charset.Value.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Reads at most <see cref="MaximumBodyLength"/> bytes, declared or chunked. A body that would
    /// exceed the limit is abandoned after the first surplus byte and yields <see langword="null"/>.
    /// </summary>
    private static async Task<byte[]?> ReadBoundedBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaximumBodyLength + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await request.Body.ReadAsync(buffer.AsMemory(total), cancellationToken);
            if (read == 0)
            {
                return buffer[..total];
            }

            total += read;
        }

        return null;
    }

    private static bool TryParseCredentials(byte[] body, out string? username, out string? password)
    {
        username = null;
        password = null;
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            // The same username/password shape the shared cookie login reads; other properties are
            // ignored, but a present credential field of another JSON type is a format error.
            foreach (var property in document.RootElement.EnumerateObject())
            {
                var isUsername = property.NameEquals("username");
                if (!isUsername && !property.NameEquals("password"))
                {
                    continue;
                }

                if (property.Value.ValueKind != JsonValueKind.String)
                {
                    return false;
                }

                if (isUsername)
                {
                    username = property.Value.GetString();
                }
                else
                {
                    password = property.Value.GetString();
                }
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static Task WriteAsync(HttpContext context, int statusCode, string body)
    {
        context.Response.StatusCode = statusCode;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.ContentType = "application/json; charset=utf-8";
        return context.Response.WriteAsync(body, context.RequestAborted);
    }
}
