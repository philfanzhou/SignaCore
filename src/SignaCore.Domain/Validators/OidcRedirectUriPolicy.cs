namespace SignaCore.Domain.Validators;

/// <summary>
/// The structural redirect-URI revalidation seam. Transport security is a deployment decision
/// (ADR 0008): <c>http</c> and <c>https</c> redirect URIs are accepted equally everywhere, so the
/// policy carries no scheme allowlist, environment privilege, or opt-in list — only the structural
/// rules of <see cref="OidcRedirectUriValidator"/>, which it re-applies to stored values at the
/// points a code is issued or a session completes.
/// </summary>
public sealed class OidcRedirectUriPolicy
{
    public static OidcRedirectUriPolicy Default { get; } = new();

    public bool Allows(string uri)
    {
        try
        {
            OidcRedirectUriValidator.ValidateAndCanonicalize(uri);
            return true;
        }
        catch (OidcClientConfigurationException) { return false; }
    }
}
