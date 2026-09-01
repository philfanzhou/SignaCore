namespace SignaCore.Domain.Models;

/// <summary>
/// The already-decoded query parameters of one <c>GET /oauth2/authorize</c> request.
/// <para>
/// The transport decodes the query exactly once and hands the result here, so the validator can
/// answer "how many times did this parameter occur?" before it reads any value. Canonical
/// <c>IN-01</c>..<c>IN-09</c> reject a repeated supported or explicitly rejected parameter before
/// its value is read, even when the duplicates are identical, and that check is impossible against
/// an API that silently collapses duplicates into one value.
/// </para>
/// </summary>
public sealed class OidcAuthorizationParameters
{
    /// <summary>OAuth parameter names are case-sensitive, so the lookup is ordinal.</summary>
    private readonly Dictionary<string, IReadOnlyList<string>> _values;

    public OidcAuthorizationParameters(
        IEnumerable<KeyValuePair<string, IReadOnlyList<string>>> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        _values = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var pair in values)
        {
            _values[pair.Key] = pair.Value;
        }
    }

    /// <summary>How many times a parameter occurred in the request.</summary>
    public int Count(string name)
    {
        return _values.TryGetValue(name, out var values) ? values.Count : 0;
    }

    /// <summary>Whether a parameter occurred at all, regardless of its value.</summary>
    public bool Contains(string name)
    {
        return Count(name) > 0;
    }

    /// <summary>
    /// The single occurrence of a parameter, or <c>null</c> when it is absent. Callers must have
    /// established that the parameter occurs at most once before reading it.
    /// </summary>
    public string? Single(string name)
    {
        return _values.TryGetValue(name, out var values) && values.Count == 1
            ? values[0]
            : null;
    }
}
