using ServiceMantle;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>
/// A snapshot source decorator that drops retired-key rows from another source's reads, so the
/// shared loader never materializes — and never fails closed on — a row the current catalog no
/// longer defines. See <see cref="RetiredSettingKeys"/> for the retirement contract.
/// </summary>
internal sealed class RetiredSettingKeyFilterSource(IServiceSettingSnapshotSource inner)
    : IServiceSettingSnapshotSource
{
    public async ValueTask<ServiceSettingSnapshotRead> LoadAsync(
        ServiceId serviceId, CancellationToken cancellationToken = default)
    {
        var read = await inner.LoadAsync(serviceId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (!read.Values.Any(value => RetiredSettingKeys.IsRetired(value.Key)))
        {
            return read;
        }

        return new ServiceSettingSnapshotRead(
            read.ServiceId,
            read.Version,
            read.Values.Where(value => !RetiredSettingKeys.IsRetired(value.Key)).ToList());
    }
}
