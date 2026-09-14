using ServiceMantle.Configuration;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Adapts the SignaCore master key to the shared sensitive-value root key contract.
/// </summary>
/// <remarks>
/// The external root secret (bootstrap file) is Base64-encoded to a stable string. The shared
/// protector derives its own HKDF domain bound to the service id and purpose, so the same master
/// material is never reused across the two protection schemes.
/// </remarks>
internal sealed class MasterKeyRootKeySource(IMasterKeyProvider masterKeyProvider)
    : IServiceSettingRootKeySource
{
    public ValueTask<string> GetRootKeyAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Convert.ToBase64String(masterKeyProvider.GetMasterKey()));
    }
}
