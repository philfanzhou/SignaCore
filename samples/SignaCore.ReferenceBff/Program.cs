using System.Net;
using Microsoft.AspNetCore.DataProtection;
using ServiceMantle.Persistence.EntityFrameworkCore;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using SignaCore.ReferenceBff;
using SignaCore.ReferenceBff.Database;
using ServiceMantle.Installation;

const string UserInfoClientName = BffIdentityCheckService.UserInfoClientName;

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

// The server-side session store (DF-07). The browser holds only the opaque key it returns; every
// token stays on the server. The expiry clock is injectable so tests can advance it.
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<MemoryTicketStore>(
    static services => new MemoryTicketStore(services.GetRequiredService<TimeProvider>()));
builder.Services.AddHostedService<TicketStoreCleanupService>();

// The named client the BFF uses to call SignaCore's UserInfo with the stored access token. The
// Bearer header only ever appears on this server-to-server leg, never toward the browser.
builder.Services.AddHttpClient(UserInfoClientName);

// The typed identity check and the local administrator authorization boundary. The identity
// check is what every identity-sensitive surface shares; the admin decision composes it with the
// BFF's own binding store and is computed fresh on every request.
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

// Keep the existing logout form token and add a BFF-specific header for Setup JSON.
builder.Services.AddAntiforgery(options => options.HeaderName = BffSetupHosting.CsrfHeader);

// The configuration is validated at startup: an incomplete configuration is a startup failure
// with a clear message, never a silently degraded run.
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
    .Validate(o => !databaseSettings.IsConfigured || BffSetupHosting.IsCallbackPathSafe(o.RedirectUri),
        "ReferenceBff:RedirectUri callback path conflicts with a reserved route.")
    .ValidateOnStart();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        // The local session cookie: server-side read, never accessible to scripts, only ever
        // issued over HTTPS. With SessionStore set (below) it carries only the opaque store key —
        // the ticket with the saved tokens never leaves the server.
        options.Cookie.Name = "signacore-bff-session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.AccessDeniedPath = "/error";
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.Redirect("/error?reason=access_denied");
            return Task.CompletedTask;
        };
    })
    .AddOpenIdConnect(options =>
    {
        var settings = builder.Configuration
            .GetSection(ReferenceBffOptions.SectionName)
            .Get<ReferenceBffOptions>() ?? new ReferenceBffOptions();

        // Everything endpoint-shaped is resolved from the Authority's Discovery document; the
        // sample never hardcodes an authorization, token, or JWKS path.
        options.Authority = settings.Authority!;
        options.ClientId = settings.ClientId!;
        options.ClientSecret = settings.ClientSecret!;
        options.ResponseType = OpenIdConnectResponseType.Code;
        // SignaCore delivers the authorization result as redirect query parameters; the
        // handler's default form_post mode is not part of SignaCore's contract.
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.UsePkce = true;
        options.CallbackPath = new Uri(settings.RedirectUri!).AbsolutePath;
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        // The tokens are saved into the server-side ticket (SessionStore above), never into the
        // browser cookie; the access token is used only for the BFF's own UserInfo call.
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = false;
        options.MapInboundClaims = false;
        options.TokenValidationParameters.ValidAudience = settings.ClientId!;
        options.TokenValidationParameters.ValidateIssuer = true;
        // The correlation cookie is the CSRF state of the handshake: Secure, HttpOnly, and
        // SameSite=None so the top-level redirect back from SignaCore can present it.
        options.CorrelationCookie = new CookieBuilder
        {
            Name = "signacore-bff-correlation",
            HttpOnly = true,
            SecurePolicy = CookieSecurePolicy.Always,
            SameSite = SameSiteMode.None,
            IsEssential = true,
            MaxAge = TimeSpan.FromMinutes(5)
        };
        options.RequireHttpsMetadata = true;
        options.Scope.Clear();
        foreach (var member in settings.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            options.Scope.Add(member);
        }

        // Discovery must be reachable before any browser is sent anywhere; an unreachable or
        // invalid authority answers with the bounded, non-sensitive error page instead of a raw
        // exception or a silent failure.
        options.Events.OnRedirectToIdentityProvider = async context =>
        {
            try
            {
                await context.Options.ConfigurationManager!.GetConfigurationAsync(
                    context.HttpContext.RequestAborted);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                context.Response.Redirect("/error?reason=authority_unreachable");
                context.HandleResponse();
            }
        };
        // Capture the identity this handshake actually verified: the validated token's issuer and
        // its single non-empty subject, byte-for-byte, into the server-side ticket properties. The
        // configured Authority is never treated as the verified issuer, and a token without
        // exactly one usable subject fails the sign-in — no identity is ever inferred or repaired.
        options.Events.OnTokenValidated = context =>
        {
            var subjectClaims = (context.Principal?.FindAll("sub") ?? [])
                .ToList();
            if (subjectClaims.Count != 1
                || string.IsNullOrEmpty(subjectClaims[0].Value)
                || string.IsNullOrEmpty(context.SecurityToken.Issuer))
            {
                context.Fail(
                    "The validated ID token must carry exactly one non-empty subject and an issuer.");
                return Task.CompletedTask;
            }

            context.Properties!.Items[ReferenceBffVerifiedIdentity.IssuerItem] = context.SecurityToken.Issuer;
            context.Properties.Items[ReferenceBffVerifiedIdentity.SubjectItem] = subjectClaims[0].Value;
            return Task.CompletedTask;
        };
        options.Events.OnRemoteFailure = context =>
        {
            // Bounded reason codes only: the failure detail never reaches the browser.
            context.Response.Redirect("/error?reason=sign_in_failed");
            context.HandleResponse();
            return Task.CompletedTask;
        };
        // A failing ID-token validation (iss, signature, exp/iat, nonce, aud) is not a remote
        // failure: it raises the authentication-failed event, and gets the same bounded page.
        options.Events.OnAuthenticationFailed = context =>
        {
            context.Response.Redirect("/error?reason=sign_in_failed");
            context.HandleResponse();
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization();

// Attach the server-side session store to the cookie handler. With SessionStore set, the cookie
// carries only the opaque key and the ticket (with the saved tokens) never leaves the server.
builder.Services
    .AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<MemoryTicketStore>((options, store) =>
    {
        options.SessionStore = store;
    });

// SignaCore's authorize contract caps the state at 128 unreserved characters; the default
// Data Protection state is longer, so the handshake uses the compact server-side format.
builder.Services.AddSingleton<CompactStateDataFormat>();
builder.Services
    .AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
    .Configure<CompactStateDataFormat>((options, stateFormat) =>
    {
        options.StateDataFormat = stateFormat;
    });

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
    var callback = new Uri(app.Configuration["ReferenceBff:RedirectUri"]!).AbsolutePath;
    // Routing supplies phase metadata before the standard OIDC handler consumes the callback.
    routes.MapGet(callback, () => Results.BadRequest());
    routes.MapGet("/bff/setup", BffSetupHosting.Form);
    routes.MapMethods("/bff/admin", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"], (HttpContext http) =>
    {
        http.Response.Headers.Allow = "GET";
        return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
    });
}

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

    // The logout form is the only state-changing surface the sample renders, and it is a POST
    // carrying the antiforgery token; the token is issued together with its cookie here.
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

routes.MapGet("/bff/login", async (
    HttpContext http,
    IOptionsMonitor<OpenIdConnectOptions> oidc,
    IOptionsMonitor<ReferenceBffOptions> settings) =>
{
    // The configuration gate: an incomplete configuration never starts a handshake. The bounded
    // reason names nothing the caller did not already know.
    ReferenceBffOptions current;
    try
    {
        current = settings.CurrentValue;
    }
    catch (OptionsValidationException)
    {
        return Results.Redirect("/error?reason=configuration_incomplete");
    }

    if (string.IsNullOrWhiteSpace(current.Authority)
        || string.IsNullOrWhiteSpace(current.ClientId)
        || string.IsNullOrWhiteSpace(current.ClientSecret)
        || string.IsNullOrWhiteSpace(current.RedirectUri))
    {
        return Results.Redirect("/error?reason=configuration_incomplete");
    }

    // Discovery is resolved before the browser is sent anywhere: an unreachable or invalid
    // authority answers with the bounded error page instead of a raw server error.
    try
    {
        var options = oidc.Get(OpenIdConnectDefaults.AuthenticationScheme);
        await options.ConfigurationManager!.GetConfigurationAsync(http.RequestAborted);
    }
    catch (Exception exception) when (exception is not OperationCanceledException)
    {
        return Results.Redirect("/error?reason=authority_unreachable");
    }

    return Results.Challenge(new AuthenticationProperties { RedirectUri = "/" });
});

routes.MapGet("/bff/diagnostics", async (HttpContext http, IOptionsMonitor<OpenIdConnectOptions> oidc) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Challenge();
    }

    // Public Discovery metadata only — this is the proof that the endpoints were resolved from
    // the authority's Discovery document rather than hardcoded anywhere in the sample.
    var configuration = await oidc.Get(OpenIdConnectDefaults.AuthenticationScheme)
        .ConfigurationManager!.GetConfigurationAsync(http.RequestAborted);
    return Results.Text(
        $"""
         <!doctype html>
         <html lang="en">
         <head><title>SignaCore Reference BFF — diagnostics</title></head>
         <body>
         <h1>Resolved from Discovery</h1>
         <p>authorization_endpoint: {WebUtility.HtmlEncode(configuration.AuthorizationEndpoint)}</p>
         <p>token_endpoint: {WebUtility.HtmlEncode(configuration.TokenEndpoint)}</p>
         <p>jwks_uri: {WebUtility.HtmlEncode(configuration.JwksUri)}</p>
         <p>issuer: {WebUtility.HtmlEncode(configuration.Issuer)}</p>
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
        await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.Redirect("/error?reason=session_expired");
    }

    if (identity.Status == BffIdentityCheckStatus.Unavailable)
    {
        return Results.Redirect("/error?reason=authority_unreachable");
    }

    return Results.Content(identity.ProfilePayload!, identity.ProfileContentType);
});

// The read-only management surface: authentication (the standard OIDC handshake) proves who signed
// in; this endpoint proves the sample's own authorization is a separate, local decision. The
// verified identity must currently be confirmed upstream AND exactly match the active local
// binding. Every response is fixed and carries no identity and no token: 200 with the constant
// body, or the manual 401/403/503 mappings — the cookie handler's 302 access-denied page is never
// used here. Anonymous requests start the standard challenge back to this fixed route only.
routes.MapGet("/bff/admin", async (
    HttpContext http,
    BffAdminAuthorizationService authorization) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/bff/admin" });
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

    switch (status)
    {
        case BffAdminAuthorizationStatus.Authorized:
            return Results.Json(new { isAdministrator = true });

        case BffAdminAuthorizationStatus.SessionInvalid:
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.StatusCode(StatusCodes.Status401Unauthorized);

        case BffAdminAuthorizationStatus.Forbidden:
            // A local denial keeps the (still valid) session; it is not a sign-out.
            return Results.StatusCode(StatusCodes.Status403Forbidden);

        default:
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
});

// The only state-changing browser surface: a POST behind antiforgery. There is no GET logout, and
// a cross-site POST without a valid token is rejected before any state changes.
routes.MapPost("/bff/logout", async (HttpContext http, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(http);
    }
    catch (AntiforgeryValidationException)
    {
        // A missing or mismatched token is a bad request; nothing is signed out.
        return Results.BadRequest();
    }

    // Terminates the BFF local session only (cookie plus server-side ticket). Coordinated
    // upstream sign-out is out of scope for this sample.
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
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
         "access_denied" => "Access was denied.",
         "sign_in_failed" => "The sign-in response failed validation.",
         "session_expired" => "Your session is no longer valid; please sign in again.",
         _ => "Unknown reason."
     }}</p>
     <p><a href="/">Back</a></p>
     </body>
     </html>
     """,
    "text/html"));

app.Run();

/// <summary>Exposed for Microsoft.AspNetCore.Mvc.Testing.</summary>
public partial class Program;
