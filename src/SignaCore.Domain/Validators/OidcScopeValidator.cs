namespace SignaCore.Domain.Validators;

public static class OidcScopeValidator
{
    public const string OpenId = "openid";
    public const string Profile = "profile";
    public const string OfflineAccess = "offline_access";

    /// <summary>Maximum length of a requested <c>scope</c> value (<c>IN-04</c>).</summary>
    public const int MaxRequestedScopeLength = 200;

    private static readonly string[] CanonicalOrder = [OpenId, Profile, OfflineAccess];
    private static readonly HashSet<string> Supported = new(CanonicalOrder, StringComparer.Ordinal);

    public static string ValidateAndCanonicalize(
        IEnumerable<string> scopes,
        bool allowRefreshToken)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var configured = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scope in scopes)
        {
            if (scope is null || !Supported.Contains(scope))
            {
                throw new OidcClientConfigurationException(
                    "The interactive scope allow list contains an unsupported value.");
            }

            if (!configured.Add(scope))
            {
                throw new OidcClientConfigurationException(
                    "The interactive scope allow list contains a duplicate value.");
            }
        }

        if (!configured.Contains(OpenId))
        {
            throw new OidcClientConfigurationException(
                "The interactive scope allow list must contain openid.");
        }

        if (configured.Contains(OfflineAccess) && !allowRefreshToken)
        {
            throw new OidcClientConfigurationException(
                "offline_access requires interactive refresh tokens to be enabled.");
        }

        return string.Join(' ', CanonicalOrder.Where(configured.Contains));
    }

    /// <summary>
    /// Splits a stored canonical allow list back into its members. The stored value is produced by
    /// <see cref="ValidateAndCanonicalize"/>, so it is already normal-ordered and duplicate-free.
    /// </summary>
    public static IReadOnlySet<string> ParseCanonical(string canonicalScopes)
    {
        ArgumentNullException.ThrowIfNull(canonicalScopes);

        return new HashSet<string>(
            canonicalScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            StringComparer.Ordinal);
    }

    /// <summary>
    /// Validates the <c>scope</c> value of an authorization request against the same supported set
    /// and canonical order used for registration, plus the client's current allow list
    /// (<c>IN-04</c>).
    /// <para>
    /// Attacker-controlled input gets a <c>Try</c> shape rather than the configuration exception,
    /// but the membership rules are the ones above rather than a second copy: an unknown member, a
    /// duplicate member, a missing <c>openid</c>, or a member outside the current allow list all
    /// fail. The result is never silently narrowed to the permitted subset.
    /// </para>
    /// </summary>
    public static bool TryValidateRequested(
        string? value,
        IReadOnlySet<string> allowedScopes,
        bool allowRefreshToken,
        out string canonicalScope)
    {
        ArgumentNullException.ThrowIfNull(allowedScopes);
        canonicalScope = string.Empty;

        if (value is null
            || value.Length == 0
            || value.Length > MaxRequestedScopeLength
            || value.Any(character => character < 0x20 || character >= 0x7f))
        {
            return false;
        }

        var requested = new HashSet<string>(StringComparer.Ordinal);

        // No RemoveEmptyEntries: a doubled or leading delimiter produces an empty member, and an
        // empty member is not a supported scope.
        foreach (var member in value.Split(' '))
        {
            if (!Supported.Contains(member) || !requested.Add(member))
            {
                return false;
            }

            if (!allowedScopes.Contains(member))
            {
                return false;
            }
        }

        if (!requested.Contains(OpenId))
        {
            return false;
        }

        if (requested.Contains(OfflineAccess) && !allowRefreshToken)
        {
            return false;
        }

        canonicalScope = string.Join(' ', CanonicalOrder.Where(requested.Contains));
        return true;
    }
}
