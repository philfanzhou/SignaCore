using System.Collections.Frozen;

namespace SignaCore.Domain.Validators;

/// <summary>Immutable transport trust from the activated host policy; registration remains exact.</summary>
public sealed class OidcRedirectUriPolicy
{
    private readonly FrozenSet<string> _httpOrigins;
    public static OidcRedirectUriPolicy Default { get; } = new(false, []);
    public bool IsDevelopment { get; }
    public OidcRedirectUriPolicy(bool isDevelopment, IEnumerable<string> httpOrigins)
    {
        IsDevelopment = isDevelopment;
        _httpOrigins = httpOrigins.ToFrozenSet(StringComparer.Ordinal);
    }
    internal bool AllowsHttpAuthority(string authority)
    {
        var hasPort = authority.StartsWith('[') ? !authority.EndsWith(']') : authority.Contains(':');
        return HostedLoginHttpTestOrigin.TryCanonicalize("http://" + authority + (hasPort ? "" : ":80"), out var origin)
            && _httpOrigins.Contains(origin);
    }
    /// <summary>Validation-only policy for an operation that removes one row and adds none.</summary>
    public OidcRedirectUriPolicy ForRegistrationRemoval(IEnumerable<string> retainedUris)
    {
        var origins = _httpOrigins.ToHashSet(StringComparer.Ordinal);
        foreach (var uri in retainedUris)
        {
            if (!uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) continue;
            var authority = uri[7..].Split(['/', '?'])[0];
            var hasPort = authority.StartsWith('[') ? !authority.EndsWith(']') : authority.Contains(':');
            if (HostedLoginHttpTestOrigin.TryCanonicalize("http://" + authority + (hasPort ? "" : ":80"), out var origin))
                origins.Add(origin);
        }
        return new(true, origins);
    }

    public bool Allows(string uri)
    {
        try
        {
            OidcRedirectUriValidator.ValidateAndCanonicalize(uri, IsDevelopment, this);
            return true;
        }
        catch (OidcClientConfigurationException) { return false; }
    }
}
