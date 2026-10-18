# Gateway Auth Capabilities: Test Plan

## Required coverage

- All three SMS modes, with and without a provider profile, return exactly two boolean fields
  with the documented values and `passwordEnabled=true`.
- A committed policy change, through the admin API or a direct database update, changes only that
  application's next answer, without a restart.
- Missing, wrong, unknown, inactive, and expired credentials return the generic 401 body with
  `no-store`; a user access token, a management bearer session, a management cookie, or an
  identity cookie alone cannot authenticate.
- Injected selectors (`?appId=`, `?app_id=`, a request body) never change the inspected
  application.
- Reads change no account, login, admission, OTP, session, refresh-token, login-history,
  login-attempt, or registration row, and responses and captured logs contain no secret, provider
  profile, or internal failure reason.
- After a read with SMS enabled and a change to `Disabled`, fresh `/api/auth/sms-code` and
  `/api/auth/token` (`grantType=sms`) requests return the existing disabled failure; re-enabling
  restores the approved/provisioned-account behavior; another application is unaffected.
- A cancelled request propagates `OperationCanceledException` from the authentication boundary
  and publishes no validated application.

## Test layers

- Unit tests: `GatewayControllerTests` (mode mapping, `no-store`, fail-closed without a validated
  application) and `AuthenticationHandlerCancellationTests` (challenge headers and body,
  cancellation).
- HTTP integration tests: `GatewayAuthCapabilitiesTests` run the host through
  `WebApplicationFactory` on a private SQLite file with a fake SMS sender;
  `IdentityHttpEndpointsTests.PublicRoutes_AreRegisteredExactlyOnce` pins the route.
- The route has no provider-specific database behavior; the existing database contract matrix
  covers the registration read.
