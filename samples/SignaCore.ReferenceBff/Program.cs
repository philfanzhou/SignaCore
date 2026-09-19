using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using SignaCore.ReferenceBff;

var builder = WebApplication.CreateBuilder(args);

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
        // issued over HTTPS. It carries no token material at all (SaveTokens stays false).
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
        options.SaveTokens = false;
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

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext http) => Results.Text(
    http.User.Identity?.IsAuthenticated == true
        ? $"""
          <!doctype html>
          <html lang="en">
          <head><title>SignaCore Reference BFF</title></head>
          <body>
          <h1>Signed in</h1>
          <p>Subject: {http.User.FindFirst("sub")?.Value ?? "(none)"}</p>
          <p>Name: {http.User.FindFirst("name")?.Value ?? "(none)"}</p>
          <p><a href="/bff/diagnostics">Diagnostics</a></p>
          </body>
          </html>
          """
        : """
          <!doctype html>
          <html lang="en">
          <head><title>SignaCore Reference BFF</title></head>
          <body>
          <h1>SignaCore Reference BFF</h1>
          <p><a href="/bff/login">Sign in with SignaCore</a></p>
          </body>
          </html>
          """,
    "text/html"));

app.MapGet("/bff/login", async (
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

app.MapGet("/bff/diagnostics", async (HttpContext http, IOptionsMonitor<OpenIdConnectOptions> oidc) =>
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
         <p>authorization_endpoint: {configuration.AuthorizationEndpoint}</p>
         <p>token_endpoint: {configuration.TokenEndpoint}</p>
         <p>jwks_uri: {configuration.JwksUri}</p>
         <p>issuer: {configuration.Issuer}</p>
         </body>
         </html>
         """,
        "text/html");
});

app.MapGet("/error", (string? reason) => Results.Text(
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
