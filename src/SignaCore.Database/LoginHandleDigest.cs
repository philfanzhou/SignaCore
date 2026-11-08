namespace SignaCore.Database;

/// <summary>
/// Converts one-time <c>login_handle</c> values into the one-way value persisted in
/// <c>authorization_requests.handle_digest</c>. The representation is deliberately the same
/// versioned <c>sha256:</c> notation <see cref="RefreshTokenDigest"/> uses, so the database holds a
/// single digest vocabulary and a future algorithm upgrade stays distinguishable per row.
/// The plaintext handle is returned to the caller exactly once at creation and is never persisted,
/// logged, or accepted back in this form (<c>DF-05</c>).
/// </summary>
public static class LoginHandleDigest
{
    public const string Prefix = Sha256Digest.DefaultPrefix;

    /// <summary><c>Prefix.Length + 64</c> lowercase hex characters.</summary>
    public const int EncodedLength = 71;

    public static string Compute(string loginHandle) =>
        Sha256Digest.Compute(Prefix, loginHandle);

    public static bool IsDigest(string value) =>
        Sha256Digest.IsDigest(value, Prefix, EncodedLength);

    public static string EnsureDigest(string value) => IsDigest(value) ? value : Compute(value);

    /// <inheritdoc cref="Sha256Digest.Matches"/>
    public static bool Matches(string computedDigest, string storedDigest) =>
        Sha256Digest.Matches(computedDigest, storedDigest);
}
