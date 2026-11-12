// ADR 0010 stage 4: the generic-path sample. This application integrates with SignaCore using
// only the framework's own OpenID Connect handler — no SignaCore package — over the standard
// OIDC surfaces: Discovery, the authorization endpoint (code + PKCE S256), the token endpoint,
// and the standard end_session_endpoint published since stage 1.
//
// Configuration (environment variables or any other source):
//   GenericOidc:Authority             e.g. https://identity.example.com
//   GenericOidc:ClientId              a Confidential, code-flow, per-application-audience client
//   GenericOidc:ClientSecret
//   GenericOidc:RedirectUri           e.g. https://app.example.com/signin-oidc   (registered)
//   GenericOidc:PostLogoutRedirectUri e.g. https://app.example.com/signout-callback-oidc (registered)
//
// SignaCore registration requirements: Confidential client, Authorization Code enabled,
// PerApplication audience, the exact redirect URI above, and the exact post-logout URI above.

using Microsoft.AspNetCore.Authentication;

namespace SignaCore.GenericOidc;
public sealed class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var authority = Required(builder.Configuration, "GenericOidc:Authority");
        var redirectUri = Required(builder.Configuration, "GenericOidc:RedirectUri");
        var postLogoutRedirectUri = Required(builder.Configuration, "GenericOidc:PostLogoutRedirectUri");

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = "Cookies";
            options.DefaultChallengeScheme = "oidc";
            options.DefaultSignOutScheme = "oidc";
        })
            .AddCookie("Cookies")
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = authority;
                options.ClientId = Required(builder.Configuration, "GenericOidc:ClientId");
                options.ClientSecret = Required(builder.Configuration, "GenericOidc:ClientSecret");
                options.ResponseType = "code";
                // The framework default: PKCE S256, exactly what SignaCore requires.
                options.UsePkce = true;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.SaveTokens = true;
                options.MapInboundClaims = false;
                options.CallbackPath = "/signin-oidc";
                options.SignedOutCallbackPath = "/signout-callback-oidc";
                options.SignedOutRedirectUri = postLogoutRedirectUri;
                // Plain-HTTP authorities are a deployment decision (SignaCore ADR 0008); the
                // framework requires this explicit opt-in because its default assumes a public
                // HTTPS authority.
                if (builder.Configuration["GenericOidc:RequireHttpsMetadata"] is { } requireHttps)
                {
                    options.RequireHttpsMetadata = bool.Parse(requireHttps);
                }
            });

        builder.Services.AddAuthorization();

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/", () => "SignaCore generic-path sample. Visit /challenge to sign in.");

        app.MapGet("/challenge", () => Results.Challenge());

        app.MapGet("/me", (System.Security.Claims.ClaimsPrincipal user) => Results.Ok(new
        {
            user.Identity!.Name,
            Claims = user.Claims.Select(claim => new { claim.Type, claim.Value }).ToArray(),
        })).RequireAuthorization();

        // Ends the local cookie session first, then redirects the browser to SignaCore's standard
        // end_session_endpoint with the stored ID token as id_token_hint — the generic handler
        // reads the endpoint straight out of SignaCore's Discovery document.
        app.MapPost("/signout", async (HttpContext context) =>
        {
            await context.SignOutAsync("Cookies");
            await context.SignOutAsync("oidc");
        });

        app.MapGet("/signout-callback-oidc", () => Results.Text(
            "Signed out. The SignaCore identity session has ended and this application's session cookie is gone.",
            "text/plain"));

        app.Run();
    }

    private static string Required(IConfiguration configuration, string key) =>
        configuration[key]
        ?? throw new InvalidOperationException($"The required setting '{key}' is missing; the generic-path sample refuses to start half-configured.");
}
