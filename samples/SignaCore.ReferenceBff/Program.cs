using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.Relational.DataProtection;
using SignaCore.Client.AspNetCore;
using SignaCore.ReferenceBff.Database;
using SignaCore.ReferenceBff;
using System.Net;

const string UserInfoClientName = BffIdentityCheckService.UserInfoClientName;
const string BffRoutePrefix = "/bff";

if (SetupCodeCommand.IsRequested(args))
{
    using var cancellation = new CancellationTokenSource();
    ConsoleCancelEventHandler cancelHandler = (_, signal) =>
    {
        signal.Cancel = true;
        cancellation.Cancel();
    };
    Console.CancelKeyPress += cancelHandler;
    try
    {
        var exitCode = await SetupCodeCommand.RunAsync(
            args, new SetupCodeTerminal(), SetupCodeCommand.CreateSession, cancellation.Token);
        Environment.ExitCode = exitCode;
        if (exitCode != 0)
        {
            try { Console.Error.WriteLine(SetupCodeCommand.ErrorCategory(exitCode)); }
            catch (Exception) { /* A closed error stream must not expose an exception. */ }
        }
    }
    finally
    {
        Console.CancelKeyPress -= cancelHandler;
    }

    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.AddServiceMantleSerilog(options =>
{
    var logging = builder.Configuration.GetSection("Logging:ServiceMantle");
    options.MinimumLevel = logging.GetValue("MinimumLevel", LogLevel.Information);
    options.IncludeScopes = logging.GetValue("IncludeScopes", true);
    options.FlushTimeout = logging.GetValue("FlushTimeout", TimeSpan.FromSeconds(2));
});
BffLogging.AddServices(builder.Services);

// The named client the BFF uses for its own authority reads: the UserInfo call behind /bff/me
// and the Discovery document behind /bff/me and /bff/diagnostics. The Bearer header only ever
// appears on the server-to-server UserInfo leg, never toward the browser.
builder.Services.AddHttpClient(UserInfoClientName);

// The typed identity check and the local administrator authorization boundary. The identity
// check is what every identity-sensitive surface shares; the admin decision composes it with the
// BFF's own binding store and is computed fresh on every request.
builder.Services.AddScoped<BffAuthorityMetadataReader>();
builder.Services.AddScoped<BffIdentityCheckService>();
builder.Services.AddScoped<BffAdminAuthorizationService>();

// The BFF's own database: fully optional, and when present it is the caller-migrated binding
// storage. A partial configuration is a startup failure; nothing migrates or seeds here.
var databaseSettings = ReferenceBffDatabaseSetup.Read(builder.Configuration);
if (databaseSettings.IsConfigured)
{
    // Share singleton provider options with the factory; the scoped context below keeps
    // Setup's unit of work separate from the shared key repository's per-call transactions.
    builder.Services.AddDbContextFactory<ReferenceBffDbContext>(
        options => ReferenceBffDatabaseSetup.ConfigureDbContext(options, databaseSettings));
    builder.Services.AddDataProtection()
        .SetApplicationName(ReferenceBffServiceMantle.ServiceIdValue)
        .PersistKeysToServiceMantleEfCore<ReferenceBffDbContext>(
            ReferenceBffServiceMantle.ServiceId,
            _ => builder.Configuration[ReferenceBffDatabaseSetup.RootKey]!);
    builder.Services.AddDbContext<ReferenceBffDbContext>(
        options => ReferenceBffDatabaseSetup.ConfigureDbContext(options, databaseSettings),
        optionsLifetime: ServiceLifetime.Singleton);
    builder.Services.AddScoped<ManagementRoleBindingStore>();
    BffSetupHosting.AddSetup(builder.Services);
}

// The configuration is validated at startup — both by the sample's own keys and by the client
// package's options over the same values — and an incomplete configuration is a startup failure
// with a clear message that names the missing key and never echoes a value.
builder.Services
    .AddOptions<ReferenceBffOptions>()
    .BindConfiguration(ReferenceBffOptions.SectionName)
    .Validate(o => !string.IsNullOrWhiteSpace(o.Authority), "ReferenceBff:Authority is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.ClientId), "ReferenceBff:ClientId is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.ClientSecret), "ReferenceBff:ClientSecret is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.RedirectUri), "ReferenceBff:RedirectUri is required.")
    .Validate(o => Uri.TryCreate(o.Authority, UriKind.Absolute, out var authority)
            && authority.Scheme == Uri.UriSchemeHttps,
        "ReferenceBff:Authority must be an absolute HTTPS URL.")
    .Validate(o => Uri.TryCreate(o.RedirectUri, UriKind.Absolute, out var redirect)
            && redirect.Scheme == Uri.UriSchemeHttps,
        "ReferenceBff:RedirectUri must be an absolute HTTPS URL.")
    .ValidateOnStart();

// The hosted-login client package owns the whole sign-in handshake and the server-side session:
// Discovery, the authorization request with state/nonce/PKCE, the hardened callback, strict
// ID-token validation, the capacity-bounded ticket store with its sweep, the session CSRF
// boundary, and the prepared-logout surface. The sample registers the package's scheme as the
// default so its own routes challenge into the package's start endpoint.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = SignaCoreHostedLoginDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = SignaCoreHostedLoginDefaults.AuthenticationScheme;
});

// The administrator-binding decision the package reports through its session endpoint. It is a
// singleton over the application services because the package resolves it once with its options.
builder.Services.AddSingleton<BffAdministratorBindingDecision>();

builder.Services.AddSignaCoreHostedLogin(options =>
{
    var settings = builder.Configuration
        .GetSection(ReferenceBffOptions.SectionName)
        .Get<ReferenceBffOptions>() ?? new ReferenceBffOptions();

    options.Authority = settings.Authority;
    options.ClientId = settings.ClientId;
    options.ClientSecret = settings.ClientSecret;
    options.RedirectUri = settings.RedirectUri;
    options.Scope = string.IsNullOrWhiteSpace(settings.Scope) ? "openid profile" : settings.Scope;

    // The sample keeps its established browser contract: the same opaque session-cookie name it
    // always issued, and the single antiforgery header its Setup surface already uses.
    options.SessionCookieName = BffSession.CookieName;
    options.AntiforgeryHeaderName = BffSetupHosting.CsrfHeader;

    // The prepared-logout return address is derived from the registered redirect URI's origin:
    // the package requires exactly <prefix>/logout/return, and the redirect URI is the one
    // externally known origin the sample already trusts. Register it in SignaCore with the
    // PostLogout kind; without that registration the upstream preparation fails and the package
    // answers its bounded local-only result instead.
    if (Uri.TryCreate(settings.RedirectUri, UriKind.Absolute, out var registered))
    {
        var origin = registered.GetComponents(
            UriComponents.Scheme | UriComponents.Host | UriComponents.Port,
            UriFormat.UriEscaped);
        options.PostLogoutRedirectUri = origin + BffRoutePrefix + "/"
            + SignaCoreHostedLoginDefaults.LogoutReturnPathSegment;
    }
});

// The package reports the administrator decision through its session endpoint; this registration
// runs after AddSignaCoreHostedLogin and replaces the default allow-all decision.
builder.Services.AddOptions<SignaCoreHostedLoginOptions>()
    .Configure<BffAdministratorBindingDecision>(
        static (options, decision) => options.AuthorizationDecision = decision);

// The sample's presentation of the package's bounded outcomes: sign-in failures redirect to the
// sample's own /error page with the closed reason, and the session status keeps the package's
// fixed JSON body.
builder.Services.AddOptions<SignaCoreHostedLoginOptions>()
    .PostConfigure(static options => options.ResponseWriter = BffResponseWriter.Instance);

builder.Services.AddAuthorization();

var app = builder.Build();

if (databaseSettings.IsConfigured)
{
    app.UseServiceMantlePipeline();
    app.MapServiceMantleSetup(BffSetupExecutor.ExecuteAsync);
}
else
{
    app.UseAuthentication();
    app.UseAuthorization();
}

var routes = app.MapGroup("");
if (databaseSettings.IsConfigured)
{
    routes.WithServiceMantlePhaseAdmission(ServiceStartupPhase.PendingSetup, ServiceStartupPhase.Completed);
    routes.MapGet("/bff/setup", BffSetupHosting.Form);
    routes.MapMethods("/bff/admin", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"], (HttpContext http) =>
    {
        http.Response.Headers.Allow = "GET";
        return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
    });
}

// The package's endpoints — start, callback (at the registered redirect URI's exact path),
// session, signin-failed, csrf, logout, and logout/return — mount under the same /bff prefix
// and the same phase admission as the sample's own routes.
routes.MapSignaCoreHostedLogin(BffRoutePrefix);

routes.MapGet("/", (HttpContext http, IAntiforgery antiforgery) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Text(
            """
            <!doctype html>
            <html lang="en">
            <head><title>SignaCore Reference BFF</title></head>
            <body>
            <h1>SignaCore Reference BFF</h1>
            <p><a href="/bff/login">Sign in with SignaCore</a></p>
            </body>
            </html>
            """,
            "text/html");
    }

    // The logout form posts to the package's prepared-logout endpoint and carries the
    // antiforgery token in its hidden field; the token is issued together with its cookie here.
    var tokens = antiforgery.GetAndStoreTokens(http);
    return Results.Text(
        $"""
         <!doctype html>
         <html lang="en">
         <head><title>SignaCore Reference BFF</title></head>
         <body>
         <h1>Signed in</h1>
         <p>Subject: {WebUtility.HtmlEncode(http.User.FindFirst("sub")?.Value ?? "(none)")}</p>
         <p>Name: {WebUtility.HtmlEncode(http.User.FindFirst("name")?.Value ?? "(none)")}</p>
         <p><a href="/bff/diagnostics">Diagnostics</a></p>
         <form method="post" action="/bff/logout">
         <input type="hidden" name="__RequestVerificationToken" value="{WebUtility.HtmlEncode(tokens.RequestToken)}" />
         <button type="submit">Sign out</button>
         </form>
         </body>
         </html>
         """,
        "text/html");
});

routes.MapGet("/bff/login", () => Results.Redirect(
    BffRoutePrefix + "/" + SignaCoreHostedLoginDefaults.StartPathSegment + "?returnUrl=%2F",
    permanent: false, preserveMethod: false));

routes.MapGet("/bff/diagnostics", async (
    HttpContext http,
    BffAuthorityMetadataReader metadata) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Challenge();
    }

    // Public Discovery metadata only — this is the proof that the endpoints were resolved from
    // the authority's Discovery document rather than hardcoded anywhere in the sample.
    BffAuthorityMetadata document;
    try
    {
        document = await metadata.ReadAsync(http.RequestAborted);
    }
    catch (Exception exception) when (exception is not OperationCanceledException)
    {
        return Results.Redirect("/error?reason=authority_unreachable");
    }

    return Results.Text(
        $"""
         <!doctype html>
         <html lang="en">
         <head><title>SignaCore Reference BFF — diagnostics</title></head>
         <body>
         <h1>Resolved from Discovery</h1>
         <p>authorization_endpoint: {WebUtility.HtmlEncode(document.AuthorizationEndpoint)}</p>
         <p>token_endpoint: {WebUtility.HtmlEncode(document.TokenEndpoint)}</p>
         <p>jwks_uri: {WebUtility.HtmlEncode(document.JwksUri)}</p>
         <p>issuer: {WebUtility.HtmlEncode(document.Issuer)}</p>
         </body>
         </html>
         """,
        "text/html");
});

// The server-side profile read: the BFF presents its stored access token to SignaCore's UserInfo
// endpoint (resolved from Discovery) over the named backchannel. The token and the Bearer header
// exist only on this leg. The typed identity check owns the whole upstream conversation: an
// upstream 401 (or a subject the authority no longer confirms) tears the local session down —
// fail closed, never keep a signed-in appearance. The success contract is unchanged: the profile
// payload SignaCore returned, verbatim.
routes.MapGet("/bff/me", async (
    HttpContext http,
    BffIdentityCheckService identityCheck) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Challenge();
    }

    BffIdentityCheckResult identity;
    try
    {
        identity = await identityCheck.CheckAsync(http, http.RequestAborted);
    }
    catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
    {
        // The caller abandoned the request; the session is untouched and nothing half-written.
        throw;
    }

    // The caller is observed once more before anything is classified: no session is torn down
    // and no profile leaves the host for a request that is already gone.
    http.RequestAborted.ThrowIfCancellationRequested();

    if (identity.Status == BffIdentityCheckStatus.SessionInvalid)
    {
        // A session whose upstream identity is gone (no token, an upstream 401, or an unconfirmed
        // subject) cannot project a profile: sign out and answer the bounded page. The upstream
        // payload is never echoed into any failure.
        await BffSession.RevokeAsync(http, http.RequestAborted);
        return Results.Redirect("/error?reason=session_expired");
    }

    if (identity.Status == BffIdentityCheckStatus.Unavailable)
    {
        return Results.Redirect("/error?reason=authority_unreachable");
    }

    return Results.Content(identity.ProfilePayload!, identity.ProfileContentType);
});

// The read-only management surface: authentication (the package's hosted-login handshake) proves
// who signed in; this endpoint proves the sample's own authorization is a separate, local
// decision. The verified identity must currently be confirmed upstream AND exactly match the
// active local binding. Every response is fixed and carries no identity and no token: 200 with
// the constant body, or the manual 401/403/503 mappings. Anonymous requests start the package's
// challenge, which returns to this fixed route and nowhere else.
routes.MapGet("/bff/admin", async (
    HttpContext http,
    BffAdminAuthorizationService authorization) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Challenge();
    }

    BffAdminAuthorizationStatus status;
    try
    {
        status = await authorization.AuthorizeAsync(http, http.RequestAborted);
    }
    catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
    {
        // The caller abandoned the request: never a session verdict, never a half decision.
        throw;
    }

    // The caller is observed once more before any classification: neither the sign-out nor any
    // fixed answer runs for a request that is already gone.
    http.RequestAborted.ThrowIfCancellationRequested();

    http.RequestServices.GetRequiredService<BffOperationLog>()
        .Record(BffLogOperation.Authorization, status, http.RequestAborted);
    switch (status)
    {
        case BffAdminAuthorizationStatus.Authorized:
            return Results.Json(new { isAdministrator = true });

        case BffAdminAuthorizationStatus.SessionInvalid:
            await BffSession.RevokeAsync(http, http.RequestAborted);
            return Results.StatusCode(StatusCodes.Status401Unauthorized);

        case BffAdminAuthorizationStatus.Forbidden:
            // A local denial keeps the (still valid) session; it is not a sign-out.
            return Results.StatusCode(StatusCodes.Status403Forbidden);

        default:
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
});

routes.MapGet("/error", (string? reason) => Results.Text(
    $"""
     <!doctype html>
     <html lang="en">
     <head><title>SignaCore Reference BFF — error</title></head>
     <body>
     <h1>Sign-in could not complete</h1>
     <p>Reason: {reason switch
     {
         "authority_unreachable" => "The sign-in server is unreachable or its discovery document is invalid.",
         "configuration_incomplete" => "The reference BFF configuration is incomplete.",
         "invalid_return_url" => "The return address was not a local path.",
         "invalid_response" => "The sign-in response was not usable.",
         "access_denied" => "Access was denied.",
         "state_mismatch" => "The sign-in response did not match the pending sign-in.",
         "issuer_mismatch" => "The sign-in response did not come from the expected sign-in server.",
         "token_exchange_failed" => "The sign-in code could not be exchanged.",
         "invalid_token" => "The sign-in response failed validation.",
         "session_store_full" => "The service cannot accept more sessions right now.",
         "requires_reauthentication" => "Re-authentication is required.",
         "session_expired" => "Your session is no longer valid; please sign in again.",
         _ => "Unknown reason."
     }}</p>
     <p><a href="/">Back</a></p>
     </body>
     </html>
     """,
    "text/html"));

app.Lifetime.ApplicationStarted.Register(() => app.Services.GetRequiredService<BffOperationLog>()
    .Record(BffLogOperation.WebHost, BffLogOutcome.Started, CancellationToken.None));
app.Run();

/// <summary>Exposed for Microsoft.AspNetCore.Mvc.Testing.</summary>
public partial class Program;
