namespace SignaCore.Database.RateLimiting;

/// <summary>The finite answer of one shared budget acquisition.</summary>
public enum OidcRateLimitAcquireResult
{
    /// <summary>A permit was counted in the current window; the request may proceed.</summary>
    Granted,

    /// <summary>The window budget is exhausted. Nothing changed: the window is not extended.</summary>
    Rejected,

    /// <summary>
    /// The store could not decide. The request must not proceed; a permit may have been consumed
    /// by a statement whose commit outcome is unknown, but none is ever granted this way.
    /// </summary>
    Unavailable
}

/// <summary>
/// The shared OIDC rate-limit budget store of PS-24: one row per policy and protected partition,
/// counted atomically by the database clock. Each call is its own unit of work on its own
/// connection and never shares a transaction with request-scoped persistence.
/// <para>
/// Not registered in DI and not wired into any HTTP pipeline yet (#381 enables it).
/// </para>
/// </summary>
public interface IOidcRateLimitStore
{
    /// <summary>
    /// Counts one permit for <paramref name="policy"/> and <paramref name="partitionDigest"/>.
    /// </summary>
    /// <param name="policy">One of the six interactive OIDC policy names.</param>
    /// <param name="partitionDigest">The 64-character lowercase hex HMAC digest of the partition.</param>
    /// <exception cref="ArgumentException">The policy or digest is not of the fixed shape.</exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was canceled, before or after the statement ran.
    /// </exception>
    Task<OidcRateLimitAcquireResult> AcquireAsync(
        string policy,
        string partitionDigest,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes at most one batch of rows whose window expired at least the retention period ago.
    /// Returns the number of deleted rows, or <see langword="null"/> when the store was unavailable.
    /// </summary>
    Task<int?> DeleteExpiredAsync(CancellationToken cancellationToken);
}
