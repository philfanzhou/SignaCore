# Gateway Auth Capabilities: Implementation Status

The feature is implemented. Use this checklist when changing it:

- [ ] Keep the response at exactly `passwordEnabled` and `smsLoginEnabled` unless a versioned
      change is approved; add fields only as an explicit, documented contract change.
- [ ] Keep the application source as the authenticated registration; never add a selector.
- [ ] Keep the generic 401 status, body, and `no-store` header.
- [ ] If a per-application password switch is ever introduced, derive `passwordEnabled` from it
      and update this module.
- [ ] Update the HTTP route tests and the route list test together with the route.
- [ ] Update this module documentation and the integration overview.

## Consumer rollout order

1. Deploy a SignaCore version that contains this route.
2. Then deploy sites that query it. An older SignaCore has no such route, so a site that gets no
   capability answer should keep SMS login hidden, or show it and rely on the SMS endpoints' own
   failures.
