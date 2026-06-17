using Grpc.Core;

namespace QuantumZhou.Identity.Tests.Service;

/// <summary>
/// Testable ServerCallContext subclass for interceptor unit tests.
/// </summary>
public class TestServerCallContextImpl : ServerCallContext
{
    public TestServerCallContextImpl(
        Metadata? requestHeaders = null,
        Metadata? responseTrailers = null,
        string peer = "ipv4:127.0.0.1:5001")
    {
        RequestHeadersCore = requestHeaders ?? new Metadata();
        ResponseTrailersCore = responseTrailers ?? new Metadata();
        PeerCore = peer;
    }

    protected override string MethodCore => "/test.Service/Method";
    protected override string HostCore => "localhost";
    protected override DateTime DeadlineCore => DateTime.UtcNow.AddMinutes(1);
    protected override Metadata RequestHeadersCore { get; }
    protected override CancellationToken CancellationTokenCore => CancellationToken.None;
    protected override string PeerCore { get; }
    protected override AuthContext AuthContextCore => new("localhost", new Dictionary<string, List<AuthProperty>>());
    protected override ContextPropagationToken? CreatePropagationTokenCore(ContextPropagationOptions? options) => null;
    protected override Metadata ResponseTrailersCore { get; }
    protected override Status StatusCore { get; set; }
    protected override WriteOptions? WriteOptionsCore { get; set; }

    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
}
