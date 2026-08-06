namespace QuantumZhou.Identity.Domain.Services.Sms;

public sealed class SmsSenderResolver
{
    private readonly IReadOnlyDictionary<string, ISmsSender> _senders;
    private readonly SmsOptions _options;

    public SmsSenderResolver(IEnumerable<ISmsSender> senders, SmsOptions options)
    {
        _senders = senders.ToDictionary(sender => sender.Provider, StringComparer.OrdinalIgnoreCase);
        _options = options;
    }

    public (ISmsSender Sender, SmsProviderProfile Profile) Resolve(string profileKey)
    {
        if (!_options.Profiles.TryGetValue(profileKey, out var profile))
            throw new InvalidOperationException("The application's SMS provider profile is not configured.");
        if (!_senders.TryGetValue(profile.Provider, out var sender))
            throw new InvalidOperationException("The configured SMS provider is unavailable.");
        return (sender, profile);
    }
}
