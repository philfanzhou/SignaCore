# Data Ownership

SignaCore exclusively owns identity credentials, login bindings, application secrets, signing keys, refresh tokens, OTP state, login history, and security audit records. Other services may store SignaCore account IDs as references but must not write SignaCore tables directly.

| Data | Owner | External access |
| --- | --- | --- |
| Accounts and identity bindings | SignaCore | HTTP API only |
| Password hashes and OTP MACs | SignaCore | Never exposed |
| Application secret hashes | SignaCore | Secret returned only at creation/reset |
| Signing private keys | SignaCore | Never exposed |
| Signing public keys | SignaCore | JWKS endpoint |
| JWT authorization claims | Issuer plus application callback | Signed token |
| Audit and login history | SignaCore | Administrative API |

Cross-service joins should use immutable account IDs and API calls, not shared database access.
