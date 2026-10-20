# Local exchange acceptance provider

This optional test tool reuses `IdentityServerFixture` and the actual SignaCore host, SQLite schema, token validation/issuance, gateway endpoints and OTP validation. It creates three neutral sample applications (`acceptance-alpha`, `acceptance-beta`, `acceptance-gamma`), all six directed trusts and synthetic password/SMS credentials. It publishes only an ephemeral numeric-loopback address and account/issuer/audience metadata to the requested JSON file.

```sh
dotnet run --project tests/SignaCore.ExchangeAcceptanceHost --configuration Release -- /absolute/path/provider.json "$PWD"
```

Keep this process running while an HTTP consumer acceptance harness runs. It uses the existing fixture password account (`http_contract_admin` / `HttpContract123`) and sample application secrets `synthetic-alpha-secret`, `synthetic-beta-secret`, `synthetic-gamma-secret`. Three synthetic phones (`13900000001`–`13900000003`) map to the same account. No SMS leaves the process; `GET /__otp?phone=<E164>` reads the fake sender's delivered code so the real OTP verification path can run.

The consumer may configure each sample application's callback with numeric-loopback `POST /__control` JSON `{ application: "beta", callbackUrl: "http://127.0.0.1:PORT/api/auth/callback" }`. This test host permits only numeric-loopback callback hosts through the existing validator and uses an HTTP handler without redirects. Production callback policy is unchanged. Consumer business claims and authorization stay in the consumer's actual callback and backend.

`POST /__control` also accepts `accountActive`, or `removeTrustFrom`/`removeTrustTo` sample application names, for negative acceptance cases. These controls exist only in this explicitly launched, owned loopback fixture. They are never registered by the production host. Stop the process with Ctrl+C to dispose the fixture database and temporary bootstrap files; delete its output JSON afterward. No production settings or database is used.
