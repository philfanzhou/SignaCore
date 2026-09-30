# Error Handling

ServiceMantle Problem Details handles unexpected endpoint failures in the Bootstrap, Setup, and
normal host. `ExceptionHandlingMiddleware` covers only middleware before that shared pipeline.
Controllers return expected validation, OAuth/OIDC, and management failures explicitly.

## HTTP exception boundaries

Each host calls `UseSignaCoreSharedHttpPipeline` once. Its request-private marker prevents the outer
fallback from logging or serializing failures rethrown after entry. The marker is never shared across
requests. No broad `ArgumentException` or `InvalidOperationException` mapping is registered: current
throw sites represent internal invariants, while expected client errors have explicit results.

| Path | Previous behavior | Current behavior |
| --- | --- | --- |
| Unexpected endpoint failure, including argument/state invariant failures | Shared 500 | Unchanged: 500, `application/problem+json`, exactly `type`, `title`, `status`, `correlationId`, `errorCode` |
| Explicit OAuth/OIDC or management rejection | Protocol-specific response | Unchanged |
| Pre-pipeline argument/state/unknown failure | Local 400/409/500 | Always 500, `application/json`, exactly PascalCase `Status`, `Title`, `Detail` |
| Caller cancellation before response starts | Could be swallowed by outer fallback | Propagates with the original request token; no fabricated response |
| Shared error-response write failure | Could trigger a second fallback | Propagates; no second serializer or outer error log |
| Failure after response starts | Sent response retained | Unchanged; no appended error body |

The prefix fallback uses only fixed public strings and logs the exception type without the exception
instance or message. Its own failed write also propagates using `RequestAborted`. Shared errors are
logged once by ServiceMantle with a safe error code and correlation ID. Transport failure does not
promise an HTTP response. The shared library retains its existing handling for already-started
responses; this change does not alter that contract.

Rollback restores the previous outer boundary and three pipeline calls together. It restores the
prefix 400/409 behavior and cancellation swallowing; endpoint Problem Details and explicit protocol
responses remain unchanged. There is no schema or configuration migration.

## Request correlation

The shared ServiceMantle correlation middleware (`UseServiceMantleCorrelationId`, registered first in every host pipeline — Bootstrap Configuration Mode, Setup Mode, and the normal host) owns the whole correlation contract:

- A request header `x-correlation-id` is reused verbatim only when it carries exactly one value
  matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (at most 64 characters). Missing, empty, blank,
  overlong, malformed, comma-joined, and repeated headers are discarded as a whole — the value is
  never trimmed, truncated, or partially selected — and a fresh 32-character lowercase hex id is
  generated instead. The rejected raw value appears in none of the outputs.
- The resolved id is published once to the request slot, the response header (written when the
  response starts), and the request logging scope; `HttpContextExtensions.GetCorrelationId()`
  reads only the slot. It throws a fixed `InvalidOperationException` when the middleware has not
  run, so there is no raw-header fallback and no second id generation. Audit rows therefore always
  match the response header and the logs.
- The correlation middleware logs nothing itself and never swallows downstream exceptions or
  cancellation; shared Problem Details owns endpoint error logging. A
  correlation id is a log-correlation value only — not authenticated, not unique, and never an
  authorization or audit subject identity. The raw caller header stays on the request object; do
  not bypass the accessor and treat it as trusted.

## Rules

- Do not return stack traces, connection strings, credentials, tokens, OTPs, or private key material.
- Use appropriate HTTP status codes and a consistent error payload.
- Preserve cancellation rather than converting it into an internal-server error.
- Log structured context, not concatenated secret-bearing request bodies.
- Authentication failures should not reveal whether an account or token exists.
- Preserve the operation's audit commit boundary: when audit rows share a business transaction,
  an audit persistence failure fails that commit and rolls back its business changes. Do not swallow
  the failure to report business success; see [current audit commit evidence](#current-audit-commit-evidence).

Sensitive request headers are redacted by middleware. Tests cover correlation propagation (see
[request correlation](#request-correlation)), exception mapping, and header redaction.

## Current audit commit evidence

[AuditService](../../src/SignaCore.Domain/Services/AuditService.cs) stages login-history rows
through its repository, and administrative action audits are staged by the shared ServiceMantle
writer into `service_audit_logs`; the caller owns the save or explicit transaction. The current
[setup completion contract](./FirstRunSetup.md#completion-is-atomic) and
[WeChat binding design](../modules/Profile/WechatBinding/03-DESIGN.md#request-flow) document their
operation-specific transaction boundaries. Use those contracts and the implementation/test sources
below rather than assuming audit persistence is best-effort:

- [TokenIssuanceService](../../src/SignaCore.Host/Services/TokenIssuanceService.cs) commits staged
  login state and login history together, using an explicit transaction for conditional refresh
  rotation, OTP verification changes, and failed-attempt updates.
  [AuditTransactionTests](../../tests/SignaCore.Tests/Host/Controllers/AuditTransactionTests.cs)
  verifies successful shared commits and rollback on audit failure, including
  `SmsSuccess_WhenLoginHistoryInsertFails_RollsBackConsumptionAndLoginState`,
  `SmsFailure_WhenLoginHistoryInsertFails_RollsBackAttemptAndLockout`, and the Password/LDAP
  login-history failure cases.
- [SmsAdmissionService](../../src/SignaCore.Domain/Services/Sms/SmsAdmissionService.cs),
  [LdapAccountService](../../src/SignaCore.Domain/Services/Ldap/LdapAccountService.cs), and
  [WechatAdmissionService](../../src/SignaCore.Domain/Services/WeChat/WechatAdmissionService.cs)
  allow callers to stage audit rows through `beforeCommit` in their shared commit boundary.
  [WechatAdmissionDatabaseContractTests](../../tests/SignaCore.IntegrationTests/Integration/WechatAdmissionDatabaseContractTests.cs)
  fixes the binding/admission rollback contract in
  `Bind_WhenAuditInsertFails_RollsBackBindingAndAdmission`.

Rollback is limited to the failed transaction. It cannot undo an earlier commit or an external
effect such as SMS delivery; the existing [SMS delivery cancellation](#sms-delivery-cancellation)
contract describes that boundary. These references describe current behavior and define no new
OIDC state or audit policy.

## SMS delivery cancellation

`ISmsSender.SendAsync` observes cancellation before delivery starts. Alibaba Cloud and Tencent Cloud
SDK requests remain non-cancellable once issued: the sender awaits the SDK result or its configured
timeout. A cancellable `WaitAsync` wrapper would abandon observation while the provider could still
charge for and deliver the message. Senders do not discard successful SDK results through a later
cancellation check. Alibaba Cloud retains its 5-second connection and 10-second read timeouts with
automatic retries disabled; Tencent Cloud retains its 10-second HTTP timeout.

`DbOtpService` saves the pending OTP and send-limit windows before calling the sender. A successful
SDK result is staged for the caller's save, including the `SmsCodeController` audit/response path.
Cancellation after delivery starts can therefore leave the durable OTP as `PendingDelivery` even
though the message arrived; waiting for the SDK does not guarantee that the later result save commits.

Callers must treat a cancelled request as potentially delivered and must not resend solely because
cancellation was reported. Already delivered messages and committed send-limit windows cannot be
withdrawn. The development logging sender checks cancellation before logging and continues to mask
the phone number and verification code.
