// The hosted-login client package's own consumer: it names the package's public surface exactly
// the way a downstream application does — AddSignaCoreHostedLogin with its options and extension
// points, MapSignaCoreHostedLogin on the endpoint router, and the well-known defaults — so any
// breaking change to the shipped package shape surfaces here as a compile failure, not in a
// downstream build.
//
// Nothing here starts a real authority or a browser flow: the host is built, briefly kept alive,
// and stopped. The package's behavioral surface is owned by its contract tests; this file owns
// the compile surface of the published nupkg.
using System.Security.Claims;
using SignaCore.Client.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

builder.Services.AddSignaCoreHostedLogin(options =>
{
    options.Authority = builder.Configuration["OrderService:Authority"]
        ?? "https://signacore.example";
    options.ClientId = builder.Configuration["OrderService:ClientId"] ?? "order-service";
    options.ClientSecret = builder.Configuration["OrderService:ClientSecret"]
        ?? "not-a-real-secret-compile-surface-only";
    options.RedirectUri = builder.Configuration["OrderService:RedirectUri"]
        ?? "https://orders.example/auth/callback";
    options.Scope = "openid profile";
    options.SchemeSelector = context =>
        context.Request.Path.StartsWithSegments("/api") ? "OrderServiceBearer" : null;
    options.AuthorizationDecision = OrderServiceAllowAll.Instance;
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapSignaCoreHostedLogin("/auth");

app.MapGet("/orders", () => "orders")
    .RequireAuthorization(policy =>
        policy.AddAuthenticationSchemes(SignaCoreHostedLoginDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser());

app.Run();

/// <summary>A minimal neutral authorization decision, the way a consumer plugs its own in.</summary>
internal sealed class OrderServiceAllowAll : ISignaCoreAuthorizationDecision
{
    internal static readonly OrderServiceAllowAll Instance = new();

    public ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
        ClaimsPrincipal subject,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
}
