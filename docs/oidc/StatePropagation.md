# State Propagation and Invalidation

**Status: target design.** See [README](./README.md).

One question, answered once: when something is turned off, what stops working, and how soon? The
answers are scattered across five documents otherwise, and a disagreement between any two of them is
a security bug.

## The matrix

Rows are triggers. Cells say what happens and when.

| Trigger | Identity session | Unredeemed codes | Refresh tokens | Access tokens | New authorizations |
| --- | --- | --- | --- | --- | --- |
| RP-initiated logout | Revoked, immediate | Rejected at redemption | Revoked for that session, all applications | Valid until `exp`, ≤ 15 min | Denied for that session |
| Identity session idle expiry | Unusable | Rejected at redemption | Still valid | Valid until `exp` | Login required |
| Identity session absolute expiry | Unusable | Rejected at redemption | Still valid | Valid until `exp` | Login required |
| Account disabled | Every session, immediate | Rejected at redemption | Revoked, all applications | Valid until `exp` | Denied |
| Account deleted | Every session, immediate | Rejected at redemption | Revoked | Valid until `exp` | Denied |
| Application deactivated (`IsActive = false`) | Untouched | Rejected at redemption for that application | Revoked for that application | Valid until `exp` | Denied for that application |
| `allow_authorization_code` set to false | Untouched | Rejected at redemption for that application | Kept | Valid until `exp` | Denied for that application |
| `allow_refresh_token` set to false | Untouched | Untouched | Revoked for that application | Valid until `exp` | Allowed, without `offline_access` |
| Redirect URI removed | Untouched | Codes for that URI keep their 60 s | Untouched | Valid until `exp` | Denied for that URI |
| Scope removed from the allow list | Untouched | Untouched | Kept until next refresh | Valid until `exp` | Granted scope narrows |
| `/oauth2/revoke` on a refresh token | Untouched | Untouched | That token revoked | Valid until `exp` | Allowed |
| Authorization code replayed | Revoked | Other codes from that session are rejected at redemption | The family from the first redemption revoked | Valid until `exp` | Login required |
| Refresh token replayed | Untouched | Untouched | Every live descendant of that family revoked | Valid until `exp` | Allowed |
| Signing key rotated | Untouched | Untouched | Untouched | Valid until `exp`, old key stays in JWKS | Allowed |

"Immediate" means the next request that touches the artifact fails, on any instance, because
authority lives in the database rather than in the cookie or the token. It does not mean a push is
sent anywhere.

## The one column that is always "valid until `exp`"

Access tokens are self-contained and there is no revocation list or introspection endpoint in this
phase. Nothing in the table revokes one. This is the single most important thing for a downstream
service to understand: a token is a statement about a moment in the past, and validating its
signature does not re-check the account.

The mitigations, in order of how much they matter:

1. Interactive access tokens live 15 minutes, so the worst case is bounded.
2. A downstream service that needs stronger revocation checks its own state, not just the token.
3. Nothing in this design lengthens an access token's life or widens its audience.

Adding a revocation list or introspection endpoint is a later decision. It would trade a database
read on every downstream call for a shorter revocation window, and that trade belongs to a
deployment that has stated it needs it.

## Password change is absent, not silent

There is no row for "password changed" because **SignaCore has no password-change operation**.
`IPasswordCredentialRepository` exposes `Get`, `Add`, and `Exists` and no update; a password hash is
written only by first-run installation and by an administrator creating an account.

This is stated here so that no implementation task assumes an unstated default. When a
password-change or password-reset capability is added, its effect on identity sessions and refresh
families is an open decision that MUST be made by that task, not inherited from this document. The
security-relevant expectation — "change your password to lock out an intruder" — is not something
this system can satisfy today, in either direction, because the operation does not exist.

## Ordering guarantees

- Revocation is committed in the same transaction as the state change that caused it. An account
  disabled but whose sessions survive because a second write failed is not a state this design
  permits.
- Session, account, and application state changes do not mark an authorization code as consumed.
  Redemption re-checks that live state; a state failure returns `invalid_grant` without replay
  handling. Redemption and session revocation take the same identity-session row lock, so their race
  resolves one way or the other: redemption first may issue tokens before revocation recalls its
  refresh token, while revocation first rejects redemption without consuming the code.
- On PostgreSQL, revocation applies to every instance because every instance reads the same rows.
  There is no cache to invalidate, which is why the identity session has no in-memory copy.

## Cleanup

The existing 24-hour cleanup job (`CleanupIntervalHours`) gains the new tables. It removes expired
and consumed authorization codes, expired continuation handles, and identity sessions past their
absolute expiry.

Consumed codes are kept for 24 hours rather than deleted at consumption. That retention is what
makes replay detectable: a deleted code is indistinguishable from one that never existed, and both
would return `invalid_grant` — but only one of them should revoke a refresh token and raise an audit
event.
