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
server-side ticket store with periodic expiry sweep, a session CSRF boundary, a local-session-first
prepared logout, and logs and telemetry that never carry a code, `state`, `nonce`, verifier,
token, secret, or full query string.

Out of scope by design: refresh-token handling, downstream Bearer token validation, and any
business authorization — those stay with the consumer through the extension points below.

## Getting started

Register the application in SignaCore as a **Confidential** client with the Code flow enabled and
the exact callback URI registered, as described in the
[Hosted Login guide](https://github.com/philfanzhou/SignaCore/blob/main/docs/integrations/HostedLogin.md).
The callback path must be exactly `<prefix>/callback` of the prefix you map below.

```csharp
using SignaCore.Client.AspNetCore;

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

// Mount the package's endpoints: /auth/start, /auth/callback, /auth/session, /auth/csrf,
// /auth/logout, /auth/logout/return, and /auth/signin-failed.
app.MapSignaCoreHostedLogin("/auth");

// The consumer's own routes authenticate against the package's session scheme.
app.MapGet("/orders", () => "Signed-in content")
    .RequireAuthorization(policy =>
        policy.AddAuthenticationSchemes(SignaCoreHostedLoginDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser());

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

### Optional authorization before sign-in

`AuthorizationDecision` is called only when reading session status, with the verified ID-token
principal. Denied reports authorization failure while the existing session remains authenticated.
It does not prevent callback sign-in. To decide whether a **new** session may be created, explicitly
configure the optional gate (default `null`):

```csharp
options.PreSignInAuthorizationDecision = new OrderServicePreSignInDecision();
options.PreSignInAuthorizationTimeout = TimeSpan.FromSeconds(10); // default; positive, at most 30
```

Implement `ISignaCorePreSignInAuthorizationDecision.DecideAsync(context, cancellationToken)` and
return `Allowed` or `Denied`. The context supplies request-local copies of `AccessTokenPrincipal`
and `IdTokenPrincipal`, plus the verified shared `Issuer` and `Subject`; no raw tokens or handshake
values are exposed. Authorize using access-token claims and your own rules, never ID-token profile
fields as permissions. The session continues to use the ID-token principal. Both decision options
can be used together at their respective times.

Before invoking the gate, the callback validates the ID token as before, strictly validates the
SignaCore access token (1–8192 ASCII compact JWS; RS256, a published matching `kid`, `typ: at+jwt`,
one exact issuer, one string audience equal to ClientId, one non-empty subject, valid `exp`/`nbf`/
`iat`, and 30-second clock skew), and requires both verified issuer/subject pairs to match. An
actually expired access token fails even within skew. Invalid or uncorrelated tokens produce
`invalid_token` without calling the decision. This internal check supports SignaCore Confidential
PerApplication code-flow tokens; it is not a general Bearer validator or a third-party JWT API.

Only timely `Allowed` passes the final cancellation and actual-expiry checkpoints and writes a
new ticket and cookie. Denied, an unknown result, consumer exceptions, non-request cancellation,
or asynchronous timeout produce `access_denied`; existing tickets and cookies are unchanged.
Request cancellation propagates without a failure redirect or new session. Timeout cancels the
decision token; late completion cannot sign in. The ticket expires at the earlier of the verified
access-token expiry and `expires_in` measured at completed redemption, so decision wait cannot
extend its lifetime.

Return promptly with asynchronous work, honor cancellation, and only return a decision: do not
sign in or perform side effects. The package cannot sandbox synchronous blocking or stop a
non-cooperative consumer's external side effects. This gate does not revoke existing sessions or
upstream tokens, refresh tokens, or make role changes immediate for an existing session. The
consumer still protects its own logs and ticket store.

Upgrades preserve existing callback behavior while the gate is null, including opaque access-token
compatibility. To migrate, keep your Confidential/PerApplication registration and explicitly set
the gate alongside your existing session-status decision. No server contract or ticket format
changes. To roll back, remove the new option/interface use and restore the old package; consumers
that require the gate must preserve their prior authorization boundary during rollback.

## Session storage

The default ticket store is in-process, capacity-bounded (`options.TicketCapacity`), and swept of
expired entries; it does not survive restarts and does not share across replicas. Multi-instance
deployments register their own store:

```csharp
builder.Services.AddSingleton<ITicketStore>(new RedisTicketStore(/* ... */));
```

The session cookie is HttpOnly, Secure, and SameSite=Lax, and the session never outlives the
access token's expiry.

## The session CSRF boundary

Every session-authenticated unsafe method — anything but GET, HEAD, OPTIONS, and TRACE on a route
that authenticates against the package's session scheme — must present a valid antiforgery token.
The browser obtains it from `GET <prefix>/csrf`, which answers `{"token":"..."}` and sets the
matching antiforgery cookie; the front end then sends the token on every write:

```http
GET  /auth/csrf
POST /orders
X-SignaCore-CSRF: <token from /auth/csrf>
```

A missing or wrong token answers one fixed 403 and changes nothing. The header name is
configurable through `options.AntiforgeryHeaderName` (default `X-SignaCore-CSRF`). Requests your
`options.SchemeSelector` forwards to your own Bearer handler never pass through the boundary.

The boundary is user-neutral: the package issues and validates every antiforgery pair against
the per-browser cookie binding alone, never against the principal any pipeline stage presents,
so a pair works the same whether the browser fetched it before or after signing in, and a
form-token minted on your own signed-in page (issue it the same way, with an unauthenticated
principal in place) stays interchangeable with a `GET <prefix>/csrf` token.

## Sign out with prepared logout

`POST <prefix>/logout` ends the local session first and then coordinates the upstream sign-out
(the [prepared logout](https://github.com/philfanzhou/SignaCore/blob/main/docs/oidc/Logout.md)
contract; Confidential clients only). The request needs the antiforgery token exactly like any
other session write:

1. Inside a per-session gate the package removes the server-side ticket and deletes the session
   cookie — the local sign-out is done and is never rolled back.
2. It then calls `POST /oauth2/logout/requests` on the server-to-server backchannel with HTTP
   Basic client authentication, the ID token it has kept server-side since sign-in, your
   registered post-logout URI, and a fresh one-time state. One attempt, never retried.
3. The browser is redirected to the returned logout URI — but only after the package has verified
   it is same-origin and carries exactly one well-formed logout handle. A forged or cross-origin
   `logout_uri` is never followed.
4. When SignaCore finishes, it returns the browser to `<prefix>/logout/return?state=...`. The
   package accepts the state only once, only with the browser's correlation cookie, and only
   within five minutes, then redirects to `options.PostLogoutReturnPath` (default `/`).

The correlation cookie is named `<SessionCookieName>-logout-return`. When your session cookie
carries the `__Host-` prefix, that naive derivation would produce an illegal name (`__Host-`
demands Path=/ while this cookie is scoped to the logout endpoints), so the package derives
`__Secure-<rest>-logout-return` instead — the `__Secure-` prefix keeps a browser-enforced Secure
guarantee and works with the package's path scope. Every other session name keeps the historical
derivation byte for byte; cookies under a previous package version's name simply age out.

If the upstream preparation fails, times out, is cancelled, or answers an unverifiable URI, the
endpoint answers the fixed local-only result — `200 {"outcome":"local_only"}` — and the browser
stays signed out locally. Access tokens already issued remain valid downstream until they expire;
revoking them is not part of this flow.

Register the exact return URI in SignaCore with the `PostLogout` kind
(`https://orders.example/auth/logout/return`) and configure it:

```csharp
options.PostLogoutRedirectUri = "https://orders.example/auth/logout/return"; // registered in SignaCore
options.PostLogoutReturnPath = "/signed-out";                               // your fixed landing path
```

Without `PostLogoutRedirectUri` the upstream logout still happens, but SignaCore shows its own
signed-out page instead of returning the browser. Repeated or concurrent logouts revoke the local
session at most once and prepare at most once; the later request answers the same local-only
result.

## Dependencies

ASP.NET Core and the `Microsoft.IdentityModel` family only — no third-party authentication
library and no SignaCore server assembly. The package consumes only SignaCore's public HTTP
contract (Discovery, the authorization endpoint, the token endpoint, and JWKS), so it works
against any supported SignaCore server release without referencing its assemblies.
