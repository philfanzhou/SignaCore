# SignaCore Reference BFF

A minimal reference Browser-for-Frontend (BFF) that signs administrators in to a SignaCore
server through Authorization Code + PKCE (S256) and receives the callback securely.

The sample resolves the authorization, token, and JWKS endpoints from the Authority's OpenID
Connect Discovery document. Nothing is hardcoded.

> **Not production ready.** The server-side token boundary (token session storage, browser
> boundary hardening) is delivered by a later SignaCore task. Until it lands, this sample must
> not be used in any real deployment.

## Configuration

| Key | Meaning |
| --- | --- |
| `ReferenceBff:Authority` | SignaCore base address (HTTPS) |
| `ReferenceBff:ClientId` | Client id registered in SignaCore |
| `ReferenceBff:ClientSecret` | Client secret — inject through the environment or user secrets |
| `ReferenceBff:RedirectUri` | This host's HTTPS redirect URI (default path `/signin-oidc`) |
| `ReferenceBff:Scope` | Requested scope (must contain `openid`) |

The configuration is validated at startup; an incomplete configuration fails to start.

Register the redirect URI on the SignaCore application (interactive OIDC configuration) with the
code flow enabled before using the sample.

## Run

```bash
SIGNACORE_REFERENCE_BFF_CLIENT_SECRET=... \
dotnet run --project samples/SignaCore.ReferenceBff \
  --ReferenceBff:Authority=https://your-signacore-host \
  --ReferenceBff:ClientId=reference-bff \
  --ReferenceBff:RedirectUri=https://your-bff-host/signin-oidc
```

Then open `https://your-bff-host/` and follow **Sign in with SignaCore**.

## Security shape

- SignaCore credentials never pass through this BFF: the browser is redirected to SignaCore's
  authorization endpoint, and the password is posted directly to SignaCore's own login form.
- Every login uses a fresh `state`, `nonce`, and PKCE verifier; the correlation cookie is
  `Secure`, `HttpOnly`, and `SameSite=None` for the top-level redirect back.
- The ID token is validated for `iss`, signature (via JWKS), `exp`/`iat`, `nonce`, and `aud`
  (the client id). A failure of any of them fails the sign-in; no local session is established.
- A missing or mismatching `state` or correlation cookie fails the callback before any token
  exchange.
- No token material is stored in the browser; the sample stores no tokens at all.

## Scope

This is a sample consumer of SignaCore, not a product. Server-side protocol state, token
storage strategy, and deployment hardening are intentionally out of scope here.
