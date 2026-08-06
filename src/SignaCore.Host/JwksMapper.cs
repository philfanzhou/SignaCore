using Microsoft.IdentityModel.Tokens;

namespace SignaCore.Host;

/// <summary>
/// Maps an RSA security key to its public JWK representation for the
/// /.well-known/jwks discovery endpoint.
/// </summary>
public static class JwksMapper
{
    public static JwkDto ToJwk(RsaSecurityKey key)
    {
        var rsa = key.Rsa ?? throw new InvalidOperationException("Key is not RSA");
        var parameters = rsa.ExportParameters(false);
        return new JwkDto(
            "RSA",
            "sig",
            key.KeyId,
            "RS256",
            Base64UrlEncoder.Encode(parameters.Modulus!),
            Base64UrlEncoder.Encode(parameters.Exponent!));
    }
}

public sealed record JwkDto(string Kty, string Use, string Kid, string Alg, string N, string E);
