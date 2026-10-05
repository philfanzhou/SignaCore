# Real HTTP identity Cookie acceptance

`http-identity-cookie.cjs` runs through the `RealChromium` integration test, using an installed Node
runtime and Playwright Chromium. It adds no runtime/package dependency to SignaCore.

```sh
SIGNACORE_BROWSER_NODE=/path/to/node \
SIGNACORE_PLAYWRIGHT_MODULE=/path/to/playwright \
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj \
  --configuration Release --filter 'FullyQualifiedName~RealChromium'
```

The test starts the actual Testing Host on Kestrel with a completed temporary SQLite installation,
shared settings, root key and persisted Data Protection keyring. Chromium addresses the exact
allowlisted `http://10.20.30.40:5002` origin through a local forwarding proxy; the effective Host
header and browser origin remain that private IP and port. The browser therefore applies real HTTP
Cookie rules without relying on the localhost Secure Cookie exception. The independent HTTPS
callback is a neutral local TLS stub using an ephemeral certificate passed only in process memory;
certificate checking is relaxed for that stub. No HTTP callback registration is implied.

The fake SMS delivery adapter captures an OTP only in memory; all other SMS admission, OTP storage,
verification, provisioning and protocol steps run through production services. The browser submits
SMS and password forms, redeems codes with S256, checks SMS `amr` and nonce, exercises bound replay,
SSO and a Kestrel restart over the same database/keyring, prepares/completes logout, checks both
Cookies actually disappear, then proves a password is required again. It also submits wrong CSRF,
cancel, malformed state/nonce/challenge, and checks the canonical error and no-code outcomes.

Only fixed stage/result markers leave the runner. It never prints credentials, OTPs, tokens,
Cookies, URLs, queries or response bodies. Browser acceptance is skipped when the explicit runtime
variable is absent; report the separate real-browser run rather than treating that skip as proof.
