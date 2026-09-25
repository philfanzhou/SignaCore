namespace SignaCore.Host.Management;

internal enum ManagementBearerIssueStatus
{
    Issued,
    Unavailable
}

/// <summary>
/// The outcome of issuing a management bearer credential. <see cref="Token"/> is the only place
/// the plaintext exists after issuance; <see cref="ToString"/> never renders it.
/// </summary>
internal sealed class ManagementBearerIssueResult
{
    public static readonly ManagementBearerIssueResult Unavailable = new(ManagementBearerIssueStatus.Unavailable, null, null);

    private ManagementBearerIssueResult(ManagementBearerIssueStatus status, string? token, DateTimeOffset? expiresAtUtc)
    {
        Status = status;
        Token = token;
        ExpiresAtUtc = expiresAtUtc;
    }

    public ManagementBearerIssueStatus Status { get; }
    public string? Token { get; }
    public DateTimeOffset? ExpiresAtUtc { get; }

    public static ManagementBearerIssueResult Issued(string token, DateTimeOffset expiresAtUtc) =>
        new(ManagementBearerIssueStatus.Issued, token, expiresAtUtc);

    public override string ToString() => $"ManagementBearerIssueResult {{ Status = {Status} }}";
}

internal enum ManagementBearerValidationStatus
{
    Valid,
    Rejected,
    Unavailable
}

/// <summary>
/// Why a presented credential was rejected. For the caller's mapping and for tests only; every
/// reason maps to the same fixed rejection and none echoes the input.
/// </summary>
internal enum ManagementBearerRejectionReason
{
    None,
    Malformed,
    NotFound,
    Expired,
    Revoked,
    NotEligible
}

internal sealed class ManagementBearerValidationResult
{
    public static readonly ManagementBearerValidationResult Unavailable =
        new(ManagementBearerValidationStatus.Unavailable, ManagementBearerRejectionReason.None, null, null);

    private ManagementBearerValidationResult(
        ManagementBearerValidationStatus status,
        ManagementBearerRejectionReason reason,
        Guid? accountId,
        string? operatorName)
    {
        Status = status;
        Reason = reason;
        AccountId = accountId;
        OperatorName = operatorName;
    }

    public ManagementBearerValidationStatus Status { get; }
    public ManagementBearerRejectionReason Reason { get; }
    public Guid? AccountId { get; }

    /// <summary>The bootstrap administrator's credential username, as stored.</summary>
    public string? OperatorName { get; }

    public static ManagementBearerValidationResult Valid(Guid accountId, string operatorName) =>
        new(ManagementBearerValidationStatus.Valid, ManagementBearerRejectionReason.None, accountId, operatorName);

    public static ManagementBearerValidationResult Rejected(ManagementBearerRejectionReason reason) =>
        new(ManagementBearerValidationStatus.Rejected, reason, null, null);

    public override string ToString() =>
        $"ManagementBearerValidationResult {{ Status = {Status}, Reason = {Reason} }}";
}

internal enum ManagementBearerRevocationResult
{
    /// <summary>This call wrote the first revocation instant.</summary>
    Revoked,

    /// <summary>The credential is malformed, unknown, expired, or already revoked. Nothing changed.</summary>
    NotActive,

    Unavailable
}
