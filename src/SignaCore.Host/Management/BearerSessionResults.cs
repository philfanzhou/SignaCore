namespace SignaCore.Host.Management;

internal enum BearerIssueStatus
{
    Issued,
    Unavailable
}

/// <summary>
/// The outcome of issuing a management bearer credential. <see cref="Token"/> is the only place
/// the plaintext exists after issuance; <see cref="ToString"/> never renders it.
/// </summary>
internal sealed class BearerIssueResult
{
    public static readonly BearerIssueResult Unavailable = new(BearerIssueStatus.Unavailable, null, null);

    private BearerIssueResult(BearerIssueStatus status, string? token, DateTimeOffset? expiresAtUtc)
    {
        Status = status;
        Token = token;
        ExpiresAtUtc = expiresAtUtc;
    }

    public BearerIssueStatus Status { get; }
    public string? Token { get; }
    public DateTimeOffset? ExpiresAtUtc { get; }

    public static BearerIssueResult Issued(string token, DateTimeOffset expiresAtUtc) =>
        new(BearerIssueStatus.Issued, token, expiresAtUtc);

    public override string ToString() => $"BearerIssueResult {{ Status = {Status} }}";
}

internal enum BearerValidationStatus
{
    Valid,
    Rejected,
    Unavailable
}

/// <summary>
/// Why a presented credential was rejected. For the caller's mapping and for tests only; every
/// reason maps to the same fixed rejection and none echoes the input.
/// </summary>
internal enum BearerRejectionReason
{
    None,
    Malformed,
    NotFound,
    Expired,
    Revoked,
    NotEligible
}

internal sealed class BearerValidationResult
{
    public static readonly BearerValidationResult Unavailable =
        new(BearerValidationStatus.Unavailable, BearerRejectionReason.None, null, null);

    private BearerValidationResult(
        BearerValidationStatus status,
        BearerRejectionReason reason,
        Guid? accountId,
        string? operatorName)
    {
        Status = status;
        Reason = reason;
        AccountId = accountId;
        OperatorName = operatorName;
    }

    public BearerValidationStatus Status { get; }
    public BearerRejectionReason Reason { get; }
    public Guid? AccountId { get; }

    /// <summary>The bootstrap administrator's credential username, as stored.</summary>
    public string? OperatorName { get; }

    public static BearerValidationResult Valid(Guid accountId, string operatorName) =>
        new(BearerValidationStatus.Valid, BearerRejectionReason.None, accountId, operatorName);

    public static BearerValidationResult Rejected(BearerRejectionReason reason) =>
        new(BearerValidationStatus.Rejected, reason, null, null);

    public override string ToString() =>
        $"BearerValidationResult {{ Status = {Status}, Reason = {Reason} }}";
}

internal enum BearerRevocationResult
{
    /// <summary>This call wrote the first revocation instant.</summary>
    Revoked,

    /// <summary>The credential is malformed, unknown, expired, or already revoked. Nothing changed.</summary>
    NotActive,

    Unavailable
}
