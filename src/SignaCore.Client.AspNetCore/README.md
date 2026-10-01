# SignaCore.Client.AspNetCore

The official SignaCore hosted-login client for ASP.NET Core. A few lines of registration let an
application sign users in through SignaCore's hosted login page — Confidential Authorization Code
flow with PKCE S256 — and keep a server-side session: every token stays on the server, and the
browser holds only one opaque cookie.

The package owns the protocol and security duties of the client side (see
[ADR 0007](https://github.com/philfanzhou/SignaCore/blob/main/docs/adr/0007-official-hosted-login-client-package.md)):
Discovery-driven endpoint resolution with `issuer` verification, an authorization request that
carries exactly `response_type=code`, `state`, `nonce`, and an S256 PKCE challenge, a hardened
single-valued callback that validates `state` and `iss` before anything else, a one-time,
never-retried code redemption with HTTP Basic client authentication, strict ID-token validation
(RS256 via JWKS `kid`, `typ: JWT`, `iss`, `aud`, lifetime, `nonce`), a capacity-bounded
server-side ticket store with periodic expiry sweep, and logs and telemetry that never carry a
code, `state`, `nonce`, verifier, token, secret, or full query string.

Out of scope by design: refresh-token handling, CSRF and prepared logout (tracked separately),
downstream Bearer token validation, and any business authorization — those stay with the consumer
through the extension points below.

## Getting started

Register the application in SignaCore as a **Confidential** client with the Code flow enabled and
the exact callback URI registered, as described in the
[Hosted Login guide](https://github.com/philfanzhou/SignaCore/blob/main/docs/integrations/HostedLogin.md).
The callback path must be exactly `<prefix>/callback` of the prefix you map below.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

builder.Services.AddSignaCoreHostedLogin(options =>
{
    options.Authority = builder.Configuration["OrderService:Authority"]; // e.g. https://signacore.example
    options.ClientId = builder.Configuration["OrderService:ClientId"];
    options.ClientSecret = builder.Configuration["OrderService:ClientSecret"];
    options.RedirectUri = builder.Configuration["OrderService:RedirectUri"]; // e.g. https://orders.example/auth/callback
    options.Scope = "openid profile";
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Mount the package's endpoints: /auth/start, /auth/callback, /auth/session, /auth/signin-failed.
app.MapSignaCoreHostedLogin("/auth");

// The consumer's own routes authenticate against the package's session scheme.
app.MapGet("/orders", () => "Signed-in content")
    .RequireAuthorization(SignaCoreHostedLoginDefaults.AuthenticationScheme);

app.Run();
```

A browser that hits a protected route is redirected to SignaCore's hosted login page and returns
with a server-side session; `GET /auth/session` reports its state:

```json
{ "authenticated": true, "requiresReauthentication": false, "displayName": "order_manager", "authorization": 0 }
```

Once the session reaches the access token's expiry, the endpoint answers the fixed
`requiresReauthentication` status; the package never refreshes silently — the next sign-in goes
through the hosted page again.

The options are validated at startup: the Authority must be absolute HTTPS without a path (an
explicit loopback HTTP origin `http://127.0.0.1` / `http://[::1]` is accepted only in the
Development and Testing environments), and the RedirectUri must be an absolute HTTPS URI whose
path is exactly `<prefix>/callback`. A violation fails startup, and the diagnostics name the
option — never the value.

## The four extension points

1. **Authorization decision** — decide what a verified subject may do, by matching the verified
   `iss` plus `sub` against your own bindings:

   ```csharp
   options.AuthorizationDecision = new OrderServiceAuthorizationDecision();
   // ... implements ISignaCoreAuthorizationDecision.DecideAsync(ClaimsPrincipal, CancellationToken)
   //     returning Allowed or Denied; the result is reported by the session endpoint.
   ```

2. **Route prefix** — where the package's endpoints are mounted: `app.MapSignaCoreHostedLogin("/auth")`.

3. **Response format** — replace the default failure page and session-status body by implementing
   `ISignaCoreHostedLoginResponseWriter` and assigning `options.ResponseWriter`.

4. **Session and Bearer scheme selection** — per request, pick which authentication scheme serves
   it: the package's session scheme (the default) or a host-owned scheme such as your Bearer
   handler:

   ```csharp
   options.SchemeSelector = context =>
       context.Request.Path.StartsWithSegments("/api")
           ? JwtBearerDefaults.AuthenticationScheme   // your own Bearer handler
           : null;                                    // null keeps the package's session scheme
   ```

## Session storage

The default ticket store is in-process, capacity-bounded (`options.TicketCapacity`), and swept of
expired entries; it does not survive restarts and does not share across replicas. Multi-instance
deployments register their own store:

```csharp
builder.Services.AddSingleton<ITicketStore>(new RedisTicketStore(/* ... */));
```

The session cookie is HttpOnly, Secure, and SameSite=Lax, and the session never outlives the
access token's expiry.

## Dependencies

ASP.NET Core and the `Microsoft.IdentityModel` family only — no third-party authentication
library and no SignaCore server assembly. The package consumes only SignaCore's public HTTP
contract (Discovery, the authorization endpoint, the token endpoint, and JWKS), so it works
against any supported SignaCore server release without referencing its assemblies.
