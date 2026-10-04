# Hosted Login Presentation Verification

Verified on 2026-10-04 for [#510](https://github.com/philfanzhou/SignaCore/issues/510).
The page behavior and security contract remain defined by [Identity Login](./IdentityLogin.md)
and the canonical model. This record describes presentation checks and their actual scope.

## Rendered states and screenshots

Screenshots use the production `BuildLoginPage` / `BuildLocalErrorPage` rendering methods and
`LoginPageStylesheet` constant, with empty visible inputs and non-secret `preview-only` placeholders
for hidden fields. They contain no real account, phone, credential, continuation, or CSRF value.
The preview tool lives outside the repository and adds no production endpoint or dependency.

| Language | Theme | Mobile, 390px | Desktop, 1440px |
| --- | --- | --- | --- |
| English | Light | [Screenshot](../assets/hosted-login/en-light-390.png) | [Screenshot](../assets/hosted-login/en-light-1440.png) |
| English | Dark | [Screenshot](../assets/hosted-login/en-dark-390.png) | [Screenshot](../assets/hosted-login/en-dark-1440.png) |
| Simplified Chinese | Light | [Screenshot](../assets/hosted-login/zh-CN-light-390.png) | [Screenshot](../assets/hosted-login/zh-CN-light-1440.png) |
| Simplified Chinese | Dark | [Screenshot](../assets/hosted-login/zh-CN-dark-390.png) | [Screenshot](../assets/hosted-login/zh-CN-dark-1440.png) |

Additional mobile states:

- [Password only](../assets/hosted-login/zh-CN-password.png)
- [Password failure](../assets/hosted-login/zh-CN-password-error.png)
- [Invalid phone format](../assets/hosted-login/zh-CN-phone-error.png)
- [Uniform SMS-send notice](../assets/hosted-login/zh-CN-sms-sent.png)
- [SMS failure](../assets/hosted-login/zh-CN-sms-error.png)
- [Local error](../assets/hosted-login/zh-CN-local-error.png)

These images are visual evidence, not authentication results. All seven states were checked in
both languages and both themes, including states not pictured separately above.

## Browser matrix and accessibility

Bundled Playwright and Chromium ran with JavaScript disabled. The matrix covered seven states ×
two languages × two themes × four widths (320, 390, 768, 1440 CSS pixels) × normal and 200% reflow:
**224 combinations passed**. The zoom check halves the available CSS width, including the stricter
160px equivalent at the smallest viewport. It verifies layout reflow rather than claiming a
physical mobile keyboard or OS-specific zoom test.

Computed measurements found no document horizontal overflow, input/button text clipping, or
intersecting controls. The smallest measured ordinary text contrast was **6.43:1**, input boundary
contrast **3.75:1**, and focus outline versus the adjacent card surface **7.90:1**. The 3px outline
has a 3px offset, leaving the surface between the outline and the control. Every button was at
least 44px high. Long content remained vertically scrollable; no fixed card height was used.

At a 390 × 450 short viewport, Tab order was username → password → Sign in → Cancel → phone → OTP
→ Send code → SMS sign in. Shift+Tab returned to Send code, the focused action remained visible
through browser scrolling, and the computed focus outline was 3px. Notices belonged to the form
whose `aria-describedby` referenced their id. Both forms remained directly visible when enabled;
the closed SMS gate rendered one form only, as checked by the HTTP tests.

## Native browser and real Host behavior

Eight native browser cases passed: English/Chinese × successful Password sign-in/empty-field
Cancel × CSS enabled/disabled. An installed SQLite SignaCore Host served the real authorize/login
routes through a local HTTPS transport gateway. Its test-only registration pointed to a second
HTTPS port, so the browser followed the real success/cancel POST redirect across origins under
the unchanged CSP. No script was enabled, no CSP error occurred, and the Password POST retained
exactly its five original fields. Synthetic fixture credentials were used only for this runtime
check and are absent from the screenshots and this record.

Separately, production-renderer placeholder pages tested native browser controls with CSS enabled
and disabled: empty Password and SMS sign-in were stopped by `required`; Cancel submitted empty
credential fields; Send code submitted with empty OTP to the original send endpoint and acquired
no button name; SMS submit included only its own handle, CSRF, phone, OTP and action fields.
These placeholder submission checks establish browser form semantics. They do not simulate SMS
provider delivery, admission, OTP consumption, or SMS authentication; those are covered by the
real HTTP integration tests below.

## Product regression checks

The final solution Release build passed. Host unit tests passed **2133/2133**. The following
selected real HTTP suites passed **278/278**, including password-failure indistinguishability,
uniform SMS send outcomes, SMS failure bytes, OTP/admission/concurrency behavior, local rejection,
CSRF, sensitive-value scanning, language and stylesheet-route contracts:

```sh
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx --configuration Release --no-restore
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release --no-build --no-restore
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj --configuration Release --no-build --no-restore --filter "FullyQualifiedName~OAuthLogin|FullyQualifiedName~OidcSensitiveValue|FullyQualifiedName~IdentityHttpEndpoints|FullyQualifiedName~BoundedOidcFormGate"
```

The local run used a physical temporary directory on macOS. Existing repository warnings remain;
there were no build errors or test failures. Full integration, the PostgreSQL/SQLite Database
Contract Matrix, container smoke, and CodeQL remain the existing CI gates. This presentation slice
adds no dependency, API, schema, configuration, or deployment change. Reverting the rendering,
text and CSS restores the previous page without data migration; the existing one-hour CSS cache
can temporarily display the earlier stylesheet while form behavior remains usable.
