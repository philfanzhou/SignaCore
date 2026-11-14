# SignaCore.GenericOidc

This confidential client uses `Microsoft.AspNetCore.Authentication.OpenIdConnect` for hosted
sign-in and sign-out. It uses the following OIDC endpoints:

- **Discovery** — `/.well-known/openid-configuration`, including the `end_session_endpoint`
  published by stage 1;
- **Authorization endpoint** — code + PKCE S256, with the standard interaction parameters
  (`prompt`, `max_age`, `acr_values`, `response_mode=query`) delivered by stage 2;
- **Token endpoint** — confidential client authentication and authorization code redemption;
- **RP-Initiated Logout** — `GET /oauth2/session/end`, driven by the handler's own sign-out
  redirect with `id_token_hint` and the registered post-logout URI.

The integration test
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
