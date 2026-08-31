namespace SignaCore.Domain.Validators;

public static class OidcScopeValidator
{
    public const string OpenId = "openid";
    public const string Profile = "profile";
    public const string OfflineAccess = "offline_access";

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
}
