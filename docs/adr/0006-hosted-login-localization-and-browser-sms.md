# Hosted Login Localization and Browser SMS Login

- Status: Accepted
- Date: 2026-09-29
- Decision owners: SignaCore maintainers
- Extends: [ADR 0005](./0005-interactive-oidc-confidential-bff.md)

## Context

[ADR 0005](./0005-interactive-oidc-confidential-bff.md) delivered the interactive Authorization
Code flow: a consuming application redirects the browser to `GET /oauth2/authorize`, SignaCore
renders its own login page at `/oauth2/login`, and the application receives a code at its exact
registered callback. A consuming service therefore no longer needs to build a login page or collect
a SignaCore password.

Two gaps keep consuming services on their own login pages and the direct credential grants:

- The login page establishes a browser identity only with the Password credential. SMS login exists
  only as the `urn:signacore:params:oauth:grant-type:sms` grant (and the legacy `sms` grant), which
  requires each application to render its own form and send the code through
  `POST /api/auth/sms-code` with its application secret.
- The login page renders unstyled English-only HTML. The consuming audience needs Simplified
  Chinese.

Most consumers are server-side applications; a few are mobile applications.

The [canonical semantic model](../oidc/CanonicalSemanticModel.md) remains the only normative source
for state transitions, persistence, external input, and sensitive-value rules. This ADR records the
direction and its boundaries. The follow-up design task adds the canonical rows before any runtime
change; until then, the current documents describe current behavior.

## Decision

| Decision | Affected canonical rows (current) |
| --- | --- |
| The hosted login page accepts exactly two credentials: Password and SMS one-time code. LDAP and WeChat remain token-endpoint grants with no identity-login UI | `IN-10..15`, `EV-01`, `EV-17` |
| Browser SMS reuses the existing application-scoped SMS policy: the application comes only from the stored continuation, and its current `SmsLoginMode`, SMS profile, and `app_sms_accesses` admission decide the result exactly as the SMS grant does. `AutoProvision` may create an account from the login page; `ManualApproval` admits only administrator-approved phones | `PS-03`, `EV-01` |
| Sending a code from the login page is a new anonymous browser surface bound to an active `login_handle` and the login antiforgery pair. The first version relies on rate limits only — per handle, per source network, and the existing per-phone hour/day windows — with no CAPTCHA or other external dependency. Every send request answers with one uniform result, so the page does not reveal whether a phone is registered, admitted, disabled, or revoked | New `IN-*` rows; `IN-10`, `IN-14`, `DF-01` |
| An identity session records how it was authenticated. A session is established by either a Password credential or an SMS login identity, never both; the database enforces that exactly one reference is present for its auth method. PostgreSQL and SQLite migrations change symmetrically | `PS-04` |
| Reusing a live session for another application rechecks that application's current policy for the session's auth method. An SMS session proceeds only if the target application currently allows SMS login and admits that phone; otherwise the browser goes to the login page as if no usable session existed. Refresh and UserInfo apply the same check | `PS-04`, `EV-05`, `IN-26..29` |
| The ID token `amr` reflects the session's auth method: `["pwd"]` for Password and `["sms"]` for SMS ([RFC 8176](https://www.rfc-editor.org/rfc/rfc8176)). Under `profile`, `name` is the account's Password username only when a Password credential exists; a phone number never enters an ID token, access token, or UserInfo response | `PS-12`, `PS-16` |
| The login page, its local error page, and its notices are rendered in `zh-CN` or `en`, negotiated from `Accept-Language` with `en` as the fallback. No request field, stored continuation value, or new configuration key selects the language in this version. API, log, audit, exception, and `docs/` text stays English | `IN-10..15` |
| The login page may load one same-origin stylesheet (`style-src 'self'`). It stays script-free in this version; the SMS send is a full form submission that re-renders the page | Login CSP in [Identity Login](../oidc/IdentityLogin.md) |
| Identity-session lifetime is unchanged: 30 minutes idle and 12 hours absolute, and refresh does not slide the idle deadline | `PS-04`, `EV-04` |
| Mobile applications integrate through their own server-side application as a confidential client (preferred), or as a Public client with an HTTPS App Link / Universal Link callback in the system browser. Custom-scheme redirect URIs and embedded WebViews are not supported | `PS-20`, `PS-21` |

## Consequences

- A consuming server-side application can drop its login page and its direct Password/SMS grant
  calls; it keeps no user credential and receives only a code at its registered callback.
- The login page becomes an unauthenticated SMS sender. Rate limits bound the cost of abuse but do
  not prevent it; a CAPTCHA or risk-scoring step may be added later behind a separate decision.
- `identity_sessions` gains an auth-method-dependent reference. Existing rows are Password sessions
  and keep their meaning; rollback requires that no SMS session rows remain.
- An account that signs in with SMS in one application does not gain silent access to another
  application that does not admit SMS for it.
- `amr` gains a second value. A consumer that asserted `amr == ["pwd"]` must accept `["sms"]` for
  applications that enable SMS.
- Mobile users are asked to sign in again after 30 idle minutes unless their own server-side
  application keeps a longer local session and needs SignaCore only at sign-in.
- The repository rule that user-facing text is English gains one explicit exception: the hosted
  login page's rendered text.

## Alternatives considered

| Alternative | Reason rejected |
| --- | --- |
| Keep SMS login as a per-application token grant | Every consumer keeps building its own SMS form, and the browser identity session cannot represent an SMS sign-in |
| Reuse `POST /api/auth/sms-code` from the login page | It requires the application secret, which the browser must never hold, and its distinct failure messages would turn the page into a phone-number oracle |
| Add a CAPTCHA in the first version | It introduces an external dependency and a third-party script into a page that is currently script-free; rate limits are accepted as the first-version control |
| Treat any live session as usable by every application | An SMS admission is per application; silent reuse would bypass `ManualApproval` and disabled SMS policy |
| Select the language through `ui_locales` | It would add a field to the stored authorization request and a schema change for a presentation choice |
| Build the login page into the Vue administration console | The console uses the management session, needs script, and would widen the login page's CSP |
| Accept custom-scheme mobile redirect URIs | It weakens the exact HTTPS redirect contract of `PS-20`; HTTPS App Links and server-side integration cover the mobile consumers |
| Make identity-session lifetime configurable per application | Current lifetimes are accepted; changing them affects every session, refresh, and revocation rule |
