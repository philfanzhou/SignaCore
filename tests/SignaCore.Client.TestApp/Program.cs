using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SignaCore.Client.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

// The package under test, configured exactly the way a real consumer configures it.
builder.Services.AddSignaCoreHostedLogin(options =>
{
    options.Authority = builder.Configuration["ClientApp:Authority"];
    options.ClientId = builder.Configuration["ClientApp:ClientId"];
    options.ClientSecret = builder.Configuration["ClientApp:ClientSecret"];
    options.RedirectUri = builder.Configuration["ClientApp:RedirectUri"];
    options.Scope = "openid profile";
    // An unset or blank configuration leaves the option null: no post-logout redirect is
    // registered with SignaCore and the browser stays on the authority's completion page.
    var postLogoutRedirectUri = builder.Configuration["ClientApp:PostLogoutRedirectUri"];
    if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri))
    {
        options.PostLogoutRedirectUri = postLogoutRedirectUri;
    }

    options.PostLogoutReturnPath = "/signed-out";
});

// A host-owned Bearer scheme: the scheme-selection extension point decides, per request, whether
// a route authenticates against the package's session or against this handler.
builder.Services
    .AddAuthentication("TestBearer")
    .AddScheme<AuthenticationSchemeOptions, TestBearerHandler>("TestBearer", static _ => { });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapSignaCoreHostedLogin(builder.Configuration["ClientApp:Prefix"] ?? "/auth");

app.MapGet("/", () => "consumer home");

// The consumer's own route: authenticated against the package's session scheme.
app.MapGet("/dashboard", (HttpContext http) =>
        $"dashboard:{http.User.FindFirst("sub")?.Value}")
    .RequireAuthorization(policy =>
        policy.AddAuthenticationSchemes(SignaCoreHostedLoginDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser());

// A state-changing route behind the session scheme: the package's CSRF boundary must gate it.
app.MapPost("/dashboard", (HttpContext http) =>
        $"dashboard-write:{http.User.FindFirst("sub")?.Value}")
    .RequireAuthorization(policy =>
        policy.AddAuthenticationSchemes(SignaCoreHostedLoginDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser());

// The fixed local landing page of a completed prepared logout.
app.MapGet("/signed-out", () => "signed-out");

// A host-owned API route behind the consumer's own Bearer handler.
app.MapGet("/api/data", () => "api-data")
    .RequireAuthorization(policy => policy.AddAuthenticationSchemes("TestBearer")
        .RequireAuthenticatedUser());

// A Bearer-authenticated write route: it must never require the session CSRF token.
app.MapPost("/api/data", () => "api-data-written")
    .RequireAuthorization(policy => policy.AddAuthenticationSchemes("TestBearer")
        .RequireAuthenticatedUser());

app.Run();

/// <summary>Exposed for Microsoft.AspNetCore.Mvc.Testing.</summary>
public partial class Program;

/// <summary>
/// The consumer's own Bearer handler for the scheme-selection tests: it accepts exactly one
/// fixed test credential and nothing else.
/// </summary>
internal sealed class TestBearerHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    internal const string SchemeName = "TestBearer";
    internal const string AcceptedCredential = "client-pack-bearer-credential";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? header = Request.Headers.Authorization;
        if (string.Equals(header, $"Bearer {AcceptedCredential}", StringComparison.Ordinal))
        {
            var identity = new ClaimsIdentity(
                [new Claim("sub", "api-subject")], Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }

        return Task.FromResult(AuthenticateResult.NoResult());
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Bearer";
        return Task.CompletedTask;
    }
}
