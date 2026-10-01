using System.Diagnostics;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// Excludes the package's backchannel requests from HttpClient instrumentation: while a request is
/// in flight the ambient activity is cleared and restored afterwards, which is the runtime's own
/// suppression mechanism — an instrumented outgoing request with no ambient activity is not
/// recorded, and no trace context is propagated into the authority call. The ID token, client
/// secret, and handles of the flow therefore never reach traces or metrics either.
/// </summary>
internal sealed class SignaCoreBackchannelTelemetryHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var previous = Activity.Current;
        Activity.Current = null;
        try
        {
            return await base.SendAsync(request, cancellationToken);
        }
        finally
        {
            Activity.Current = previous;
        }
    }
}
