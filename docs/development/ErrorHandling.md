# Error Handling

`ExceptionHandlingMiddleware` is the final boundary for unhandled request exceptions. Controllers should return expected validation and authorization failures explicitly; unexpected failures are logged with the correlation identifier and converted to a stable JSON error response.

## Rules

- Do not return stack traces, connection strings, credentials, tokens, OTPs, or private key material.
- Use appropriate HTTP status codes and a consistent error payload.
- Preserve cancellation rather than converting it into an internal-server error.
- Log structured context, not concatenated secret-bearing request bodies.
- Authentication failures should not reveal whether an account or token exists.
- Preserve the operation's audit commit boundary: when audit rows share a business transaction,
  an audit persistence failure fails that commit and rolls back its business changes. Do not swallow
  the failure to report business success; see [current audit commit evidence](#current-audit-commit-evidence).

Sensitive request headers are redacted by middleware. Tests cover correlation propagation, exception mapping, and header redaction.

## Current audit commit evidence

[AuditService](../../src/SignaCore.Domain/Services/AuditService.cs) stages login-history and audit-log
rows through repositories; the caller owns the save or explicit transaction. The current
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
