namespace SignaCore.Database;

/// <summary>
/// Converts one-time authorization code values into the one-way value persisted in
/// <c>authorization_codes.code_digest</c>. The representation is deliberately the same versioned
/// <c>sha256:</c> notation <see cref="LoginHandleDigest"/> and <see cref="RefreshTokenDigest"/>
/// use, so the database holds a single digest vocabulary and a future algorithm upgrade stays
/// distinguishable per row. The plaintext code is returned to the caller exactly once at creation
/// and is never persisted, logged, or accepted back in this form (<c>DF-03</c>).
/// </summary>
public static class AuthorizationCodeDigest
{
    public const string Prefix = Sha256Digest.DefaultPrefix;

    /// <summary>The total encoded length: the prefix plus 64 lowercase hex characters.</summary>
    public const int EncodedLength = 71;

    public static string Compute(string authorizationCode) =>
        Sha256Digest.Compute(Prefix, authorizationCode);

    public static bool IsDigest(string value) =>
        Sha256Digest.IsDigest(value, Prefix, EncodedLength);

    public static string EnsureDigest(string value) => IsDigest(value) ? value : Compute(value);

    /// <inheritdoc cref="Sha256Digest.Matches"/>
    public static bool Matches(string computedDigest, string storedDigest) =>
        Sha256Digest.Matches(computedDigest, storedDigest);
}
