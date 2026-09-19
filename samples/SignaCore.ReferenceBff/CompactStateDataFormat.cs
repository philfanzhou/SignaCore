using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace SignaCore.ReferenceBff;

/// <summary>
/// A compact state format for the OIDC handshake. The handler's default state is a Data
/// Protection payload of several hundred characters; SignaCore's authorize contract accepts
/// 22–128 unreserved characters (<c>IN-06</c>), so the sample instead issues a random 43
/// character state and keeps the protected properties server-side until the callback presents
/// the same value. The correlation binding is unaffected: the correlation id still lives inside
/// the round-tripped properties, and the correlation cookie still decides the callback.
/// </summary>
public sealed class CompactStateDataFormat : ISecureDataFormat<AuthenticationProperties>
{
    private readonly ConcurrentDictionary<string, AuthenticationProperties> _pending = new();

    public string Protect(AuthenticationProperties data) => Protect(data, null);

    public string Protect(AuthenticationProperties data, string? purpose)
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        var state = Convert.ToBase64String(entropy).TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        _pending[state] = data;
        return state;
    }

    public AuthenticationProperties? Unprotect(string? text) => Unprotect(text, null);

    public AuthenticationProperties? Unprotect(string? text, string? purpose) =>
        text is not null && _pending.TryRemove(text, out var properties)
            ? properties
            : null;
}
