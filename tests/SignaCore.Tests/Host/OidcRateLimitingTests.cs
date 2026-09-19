using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// The partition contract of the interactive OIDC rate limits (issue #304): attacker-controlled
/// protocol values never enter the partition key, the key set is bounded, the client id
/// candidates are read from bounded carriers only, and the resolver does not touch the bodies of
/// the endpoints that parse them strictly.
/// </summary>
public sealed class OidcRateLimitingTests
{
    [Fact]
    public void ThePartitionKey_IgnoresAttackerControlledValues()
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var sequence in Enumerable.Range(0, 500))
        {
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
            context.Request.QueryString = new QueryString(
                $"?state=state-{sequence}-{Guid.NewGuid():N}&nonce=nonce-{sequence}&redirect_uri=https://evil-{sequence}.example/cb");
            keys.Add(OidcRateLimitPolicies.PartitionKey(context));
        }

        // Five hundred distinct attacker value combinations, one partition: the source network.
        var key = Assert.Single(keys);
        Assert.Equal("ip:198.51.100.7", key);
    }

    [Fact]
    public void ThePartitionKey_UsesTheClientPartitionOnlyForResolvedRegistrations()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
        context.Items[OidcRateLimitPolicies.RegisteredClientItemKey] = "registered-client";

        Assert.Equal("client:registered-client", OidcRateLimitPolicies.PartitionKey(context));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("client with spaces")]
    [InlineData("client/with/slashes")]
    [InlineData("client?with=query")]
    [InlineData("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")]
    public void ImplausibleClientIds_AreRejectedBeforeAnyCarrier(string candidate)
    {
        Assert.False(OidcRateLimitPolicies.IsPlausibleClientId(candidate));
    }

    [Fact]
    public void TheBasicHeaderClientHalf_IsDecodedAndShapeChecked()
    {
        Assert.True(OidcRateLimitPolicies.TryReadBasicClientId(
            Convert.ToBase64String(Encoding.UTF8.GetBytes("my-client:my-secret")),
            out var clientId));
        Assert.Equal("my-client", clientId);

        // Malformed base64, no separator, and oversized payloads all refuse.
        Assert.False(OidcRateLimitPolicies.TryReadBasicClientId("not-base64!!!", out _));
        Assert.False(OidcRateLimitPolicies.TryReadBasicClientId(
            Convert.ToBase64String(Encoding.UTF8.GetBytes("noseparator")), out _));
        Assert.False(OidcRateLimitPolicies.TryReadBasicClientId(
            Convert.ToBase64String(Encoding.UTF8.GetBytes("a:" + new string('x', 2000))), out _));
    }

    [Fact]
    public async Task TheCandidateRead_NeverTouchesTheLoginOrLogoutBodies()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/oauth2/login";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = new MemoryStream(
            Encoding.UTF8.GetBytes("login_handle=h&username=u&password=p"));

        var candidate = await OidcRateLimitPolicies.ReadClientIdCandidateAsync(
            context, CancellationToken.None);

        Assert.Null(candidate);
        // The strict body parse of the login action still sees every byte.
        using var reader = new StreamReader(context.Request.Body);
        var body = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        Assert.Equal("login_handle=h&username=u&password=p", body);
    }

    [Fact]
    public async Task TheResolver_ClientPartitionsARegisteredClient_AndCachesTheRead()
    {
        var repository = new Mock<IAppRegistrationRepository>();
        var reads = 0;
        repository.Setup(r => r.GetByAppIdAsync("known-client", It.IsAny<CancellationToken>()))
            .Callback(() => reads++)
            .ReturnsAsync(new AppRegistrationEntity { AppId = "known-client" });

        var invoke = BuildResolver(repository.Object);
        var context = new DefaultHttpContext();
        context.Request.Path = "/oauth2/token";
        context.Request.Method = "POST";
        context.Request.Headers.Authorization =
            $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes("known-client:secret"))}";

        await invoke(context);
        await invoke(context);

        Assert.Equal("known-client", context.Items[OidcRateLimitPolicies.RegisteredClientItemKey]);
        Assert.Equal(1, reads);
    }

    [Fact]
    public async Task TheResolver_UnknownClientsFallToTheSourceNetwork()
    {
        var repository = new Mock<IAppRegistrationRepository>();
        repository.Setup(r => r.GetByAppIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AppRegistrationEntity?)null);

        var invoke = BuildResolver(repository.Object);
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.9");
        context.Request.Path = "/oauth2/authorize";
        context.Request.QueryString = new QueryString("?client_id=unknown-client");

        await invoke(context);

        Assert.False(context.Items.ContainsKey(OidcRateLimitPolicies.RegisteredClientItemKey));
        Assert.Equal("ip:198.51.100.9", OidcRateLimitPolicies.PartitionKey(context));
    }

    [Fact]
    public async Task TheResolver_IgnoresPathsOutsideTheInteractiveEndpoints()
    {
        var repository = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        var invoke = BuildResolver(repository.Object);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/auth/token";
        context.Request.QueryString = new QueryString("?client_id=whatever");

        await invoke(context);

        repository.VerifyNoOtherCalls();
    }

    private static Func<HttpContext, Task> BuildResolver(IAppRegistrationRepository repository)
    {
        var services = new ServiceCollection();
        services.AddMemoryCache();
        services.AddSingleton(repository);
        var provider = services.BuildServiceProvider();
        var middleware = new OidcClientPartitionResolverMiddleware(
            _ => Task.CompletedTask,
            provider.GetRequiredService<IMemoryCache>(),
            provider.GetRequiredService<IServiceScopeFactory>());
        return middleware.InvokeAsync;
    }
}
