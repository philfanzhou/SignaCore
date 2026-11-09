namespace SignaCore.Database;

/// <summary>
/// Converts bearer refresh-token secrets into the one-way value persisted in the database.
/// The version prefix makes the representation distinguishable from legacy plaintext rows and
/// leaves room for a future digest upgrade without invalidating every active session.
/// </summary>
public static class RefreshTokenDigest
{
    public const string Prefix = Sha256Digest.DefaultPrefix;

    /// <summary>The total encoded length: the prefix plus 64 lowercase hex characters.</summary>
    public const int EncodedLength = 71;
    public const string PublicPrefix = "sha256-public:";

    /// <summary>The total encoded length: the public prefix plus 64 lowercase hex characters.</summary>
    public const int PublicEncodedLength = 78;

    public static string Compute(string token) => Sha256Digest.Compute(Prefix, token);

    public static string ComputePublic(string token) => Sha256Digest.Compute(PublicPrefix, token);

    public static bool IsDigest(string value) =>
        IsPublicDigest(value) || Sha256Digest.IsDigest(value, Prefix, EncodedLength);

    public static bool IsPublicDigest(string value) =>
        Sha256Digest.IsDigest(value, PublicPrefix, PublicEncodedLength);

    public static string EnsureDigest(string value) => IsDigest(value) ? value : Compute(value);
}
