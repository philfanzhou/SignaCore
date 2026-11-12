# SignaCore.GenericOidc — the generic-path sample

This sample integrates with SignaCore using **only the framework's own OpenID Connect handler**
(`Microsoft.AspNetCore.Authentication.OpenIdConnect`). It references no SignaCore package of any
kind — that is the entire point. Since [ADR 0010](../../docs/adr/0010-standards-conformant-oidc-and-generic-client-integration.md),
SignaCore publishes the standard OIDC surfaces this handler consumes:

- **Discovery** — `/.well-known/openid-configuration`, including the `end_session_endpoint`
  published by stage 1;
- **Authorization endpoint** — code + PKCE S256, with the standard interaction parameters
  (`prompt`, `max_age`, `acr_values`, `response_mode=query`) delivered by stage 2;
- **Token endpoint** — `client_secret_basic` authentication and a standard code redemption;
- **RP-Initiated Logout** — `GET /oauth2/session/end`, driven by the handler's own sign-out
  redirect with `id_token_hint` and the registered post-logout URI.

The client package `SignaCore.Client.AspNetCore` remains available and remains the right choice
when a consumer wants SignaCore's server-side ticket store, its strict response-validation
profile, and its prepared-logout transport. This sample exists to prove the other path: a
consumer that holds no SignaCore dependency can sign in and sign out against a conforming
SignaCore. The integration test
`tests/SignaCore.IntegrationTests/Integration/GenericOidcClientFlowTests.cs` drives this exact
application against the real host on every CI run.

## Registration in SignaCore

| Setting | Value |
| --- | --- |
| Client type | Confidential |
| Authorization Code | enabled |
| Audience mode | PerApplication (`aud` = the client id) |
| Scopes | `openid profile` |
| Redirect URI | exactly the configured callback, e.g. `https://app.example.com/signin-oidc` |
| PostLogout URI | exactly the configured signed-out callback, e.g. `https://app.example.com/signout-callback-oidc` |

## Run

```bash
cd samples/SignaCore.GenericOidc
dotnet run -- \
  --GenericOidc:Authority https://identity.example.com \
  --GenericOidc:ClientId my-client \
  --GenericOidc:ClientSecret "$SECRET" \
  --GenericOidc:RedirectUri https://app.example.com/signin-oidc \
  --GenericOidc:PostLogoutRedirectUri https://app.example.com/signout-callback-oidc
```

A plain-HTTP authority (an isolated or internal deployment, a SignaCore decision under ADR 0008)
needs the explicit `--GenericOidc:RequireHttpsMetadata false`; HTTPS authorities need nothing.
