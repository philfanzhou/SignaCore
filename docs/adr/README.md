# Architecture Decision Records

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](./0001-multi-provider-persistence.md) | Amended by [0004](./0004-drop-mysql-support.md) | Use EF Core provider adapters per database, with one shared model and per-provider migrations |
| [0002](./0002-database-backed-configuration.md) | Accepted | Store global configuration in the business database, with a writable protected bootstrap file and web-based setup |
| [0003](./0003-cross-application-refresh-grant.md) | Accepted | Allow a refresh token to be exchanged across applications over an administered directed trust edge, minting single-hop |
| [0004](./0004-drop-mysql-support.md) | Accepted | Withdraw MySQL/MariaDB support and move the stack to EF Core 10 |
| [0005](./0005-interactive-oidc-confidential-bff.md) | Accepted | Add interactive OIDC in staged slices for pre-registered confidential BFF clients |
| [0006](./0006-hosted-login-localization-and-browser-sms.md) | Accepted | Localize the hosted login page and add browser SMS login with rate limits, auth-method-aware sessions, and per-application reuse checks |
| [0007](./0007-official-hosted-login-client-package.md) | Accepted | Publish an official hosted-login client package with fixed responsibilities, four extension points, tag-based versioning, and a minor-minus-one compatibility promise |
| [0008](./0008-transport-security-is-a-deployment-decision.md) | Accepted | Remove all code-level HTTPS transport policies on both the host and the client package: http and https are equal inputs, structural URI rules and cookie-scheme derivation remain |
