using ServiceMantle.Installation;

namespace SignaCore.Host.Installation;

/// <summary>
/// The single place that maps the durable shared installation state to a startup phase. Both the
/// pre-host installation resolution and the normal host's phase gate snapshot source read it, so the
/// "an incomplete installation never runs the normal host" invariant has one source.
/// </summary>
internal static class SharedInstallationPhase
{
    public static ServiceStartupPhase Resolve(ServiceInstallationState? state)
        => ServiceStartupPhaseResolver.Resolve(hasBootstrapConfiguration: true, state);
}
