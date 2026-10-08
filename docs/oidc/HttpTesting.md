# Plain-HTTP deployments

The former private-network HTTP **testing** foundation — the shared
`security.hosted_login_http_test_origins` allowlist, its `Testing` environment gate, and the
`security.allow_non_https_issuer` opt-in — is retired by
[ADR 0008](../adr/0008-transport-security-is-a-deployment-decision.md). Plain HTTP is no longer a
gated test capability: `http` and `https` redirect URIs, public base URLs, issuers, hosted-login
requests, and outbound callbacks are accepted equally in every environment, and the identity and
antiforgery cookie carriers follow the request scheme (`https` selects the Secure `__Host-`
prefixed carriers, plain `http` the neutral non-Secure carriers described in the
[canonical carrier contract](./CanonicalSemanticModel.md#plain-http-cookie-carrier-ps-18--ps-19)).

Retired keys keep their stored rows ignored by every read; dropping the rows with `value=null`
after an upgrade is optional housekeeping (see [Shared settings](../development/SharedSettings.md#retired-transport-keys)).

HTTP still provides no transport confidentiality or integrity: terminate TLS in front of the
service for public deployments, isolate private-network deployments, and never share a plain-HTTP
host with high-trust HTTPS traffic. The SSRF callback gates (`Callback:AllowedDomains`,
`Callback:AllowPrivateAddresses`) are unchanged.
