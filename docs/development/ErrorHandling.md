# Error Handling

`ExceptionHandlingMiddleware` is the final boundary for unhandled request exceptions. Controllers should return expected validation and authorization failures explicitly; unexpected failures are logged with the correlation identifier and converted to a stable JSON error response.

## Rules

- Do not return stack traces, connection strings, credentials, tokens, OTPs, or private key material.
- Use appropriate HTTP status codes and a consistent error payload.
- Preserve cancellation rather than converting it into an internal-server error.
- Log structured context, not concatenated secret-bearing request bodies.
- Authentication failures should not reveal whether an account or token exists.
- Audit persistence failures must not cause the primary business operation to fail.

Sensitive request headers are redacted by middleware. Tests cover correlation propagation, exception mapping, and header redaction.

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
