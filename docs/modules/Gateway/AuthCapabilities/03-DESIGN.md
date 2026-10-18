# Gateway Auth Capabilities: Design

## Components

`GatewayAppAuthenticationHandler`, `GatewayValidationService`, `GatewayController`, and
`GatewayAuthCapabilitiesResponse`.

## Request flow

1. The `GatewayApp` authorization policy runs `GatewayAppAuthenticationHandler`, which reads the
   `X-Admin-AppId` and `X-Admin-AppSecret` headers and calls
   `GatewayValidationService.ValidateAsync` with the request's cancellation token.
2. `GatewayValidationService` loads the registration through
   `AppRegistrationRepository.GetByAppIdAsync` (a scoped `DbContext`, no cache) and rejects
   unknown, inactive, and expired registrations, public clients, and wrong secrets.
3. On success the handler stores the registration in `HttpContext.Items`; on failure the shared
   challenge writes the generic 401 with `Cache-Control: no-store`.
4. `GatewayController.GetAuthCapabilities` reads the registration with
   `HttpContext.GetValidatedApp()`, sets `Cache-Control: no-store`, and returns the two booleans.
   If no validated registration is present it throws `InvalidOperationException` (fail closed).

## Why the action does not use the controller's fallback validation

`GatewayController.ValidateGatewayRequestAsync` keeps a fallback that answers with specific
reasons such as `AppId not registered`. The capability action never calls it, so its 401 can only
ever be the generic challenge and never reveals whether an application exists.

## Persistence

The action reads the `SmsLoginMode` of the registration the authentication handler loaded for the
same request. It writes nothing. No table, column, or migration is added.

## Design constraints

- No startup snapshot, per-instance cache, or separate SMS flag: the registration row is the only
  source of truth.
- Domain code does not depend on the web host; the response type lives in the Host project.
- Async calls propagate `CancellationToken`; the action itself performs no I/O.
- Secrets are never included in responses or diagnostic payloads.
