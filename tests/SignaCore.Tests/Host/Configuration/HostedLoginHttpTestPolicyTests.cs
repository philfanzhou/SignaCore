using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Moq;
using ServiceMantle.Configuration;
using ServiceMantle;
using SignaCore.Host.Configuration;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public sealed class HostedLoginHttpTestPolicyTests
{
    [Theory]
    [InlineData("http://10.0.0.0:1")]
    [InlineData("http://10.255.255.255:65535")]
    [InlineData("http://172.16.0.0:80")]
    [InlineData("http://172.31.255.255:5002")]
    [InlineData("http://192.168.0.0:80")]
    [InlineData("http://192.168.255.255:5008")]
    [InlineData("HTTP://[FC00::]:80")]
    [InlineData("http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")]
    public void PrivateRangeBoundaries_AreAccepted(string origin) =>
        Assert.True(HostedLoginHttpTestOrigins.TryCanonicalize(origin, out _));

    [Theory]
    [InlineData("")]
    [InlineData(" http://10.0.0.1:80")]
    [InlineData("http://10.0.0.1:80 ")]
    [InlineData("https://10.0.0.1:80")]
    [InlineData("http://10.0.0.1")]
    [InlineData("http://10.0.0.1:80/")]
    [InlineData("http://10.0.0.1:80/path")]
    [InlineData("http://10.0.0.1:80?query")]
    [InlineData("http://10.0.0.1:80#fragment")]
    [InlineData("http://user@10.0.0.1:80")]
    [InlineData("http://10.0.0.1:0")]
    [InlineData("http://10.0.0.1:65536")]
    [InlineData("http://10.0.0.1:+80")]
    [InlineData("http://10.0.0.1:0x50")]
    [InlineData("http://10.0.0.1:8０")]
    [InlineData("http://10.0.0.1:80\\")]
    [InlineData("http://10.0.0.%31:80")]
    [InlineData("http://localhost:80")]
    [InlineData("http://private.example:80")]
    [InlineData("http://*.example:80")]
    [InlineData("http://10.0.0.0/8:80")]
    [InlineData("http://10.1:80")]
    [InlineData("http://167772161:80")]
    [InlineData("http://0x0a000001:80")]
    [InlineData("http://012.0.0.1:80")]
    [InlineData("http://010.0.0.1:80")]
    [InlineData("http://10.00.0.1:80")]
    [InlineData("http://10.256.0.1:80")]
    [InlineData("http://127.0.0.1:80")]
    [InlineData("http://169.254.0.1:80")]
    [InlineData("http://9.255.255.255:80")]
    [InlineData("http://11.0.0.0:80")]
    [InlineData("http://172.15.255.255:80")]
    [InlineData("http://172.32.0.0:80")]
    [InlineData("http://192.167.255.255:80")]
    [InlineData("http://192.169.0.0:80")]
    [InlineData("http://8.8.8.8:80")]
    [InlineData("http://[::1]:80")]
    [InlineData("http://[fe80::1]:80")]
    [InlineData("http://[fbff::1]:80")]
    [InlineData("http://[fe00::1]:80")]
    [InlineData("http://[2001:db8::1]:80")]
    [InlineData("http://[::ffff:10.0.0.1]:80")]
    [InlineData("http://[fc00::1%eth0]:80")]
    [InlineData("http://[fc00::1%25eth0]:80")]
    [InlineData("http://fc00::1:80")]
    [InlineData("http://[10.0.0.1]:80")]
    public void InvalidOrigins_AreRejected(string origin) =>
        Assert.False(HostedLoginHttpTestOrigins.TryCanonicalize(origin, out _));

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("[null]")]
    [InlineData("[1]")]
    [InlineData("[\"\"]")]
    [InlineData("[\"http://10.0.0.1:80\",\"HTTP://10.0.0.1:080\"]")]
    [InlineData("[\"http://[fc00::1]:80\",\"http://[FC00:0:0:0:0:0:0:1]:80\"]")]
    public void InvalidJsonOrCanonicalDuplicates_AreRejected(string json) =>
        Assert.False(HostedLoginHttpTestOrigins.TryParseJson(json, out _));

    [Fact]
    public void JsonSizeAndCount_AreBounded()
    {
        var values = Enumerable.Range(1, 33).Select(port => "http://10.0.0.1:" + port).ToArray();
        Assert.True(HostedLoginHttpTestOrigins.TryParseJson(JsonSerializer.Serialize(values[..32]), out _));
        Assert.False(HostedLoginHttpTestOrigins.TryParseJson(JsonSerializer.Serialize(values), out _));
        Assert.True(HostedLoginHttpTestOrigins.TryParseJson("[" + new string(' ', 8190) + "]", out _));
        Assert.False(HostedLoginHttpTestOrigins.TryParseJson("[" + new string(' ', 8191) + "]", out _));
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("Custom")]
    [InlineData("testing")]
    public async Task NonTestingActualEnvironment_RejectsNonemptyList(string environment)
    {
        var snapshot = await SnapshotAsync("[\"http://10.0.0.1:80\"]");
        var error = Assert.Throws<InvalidOperationException>(() => HostedLoginHttpTestPolicy.Create(snapshot, Environment(environment)));
        Assert.Equal("HTTP hosted-login test origins require the Testing environment.", error.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("[]")]
    public async Task OldAggregateOrEmptyList_RemainsDisabledInEveryEnvironment(string? json)
    {
        var snapshot = await SnapshotAsync(json);
        foreach (var name in new[] { "Testing", "Development", "Staging", "Production", "Custom" })
            Assert.False(HostedLoginHttpTestPolicy.Create(snapshot, Environment(name)).Enabled);
    }

    [Fact]
    public async Task TwoSnapshots_ProduceIndependentImmutablePolicies_AndCanonicalMembership()
    {
        var first = HostedLoginHttpTestPolicy.Create(await SnapshotAsync("[\"http://[fc00::1]:80\"]"), Environment("Testing"));
        var second = HostedLoginHttpTestPolicy.Create(await SnapshotAsync("[\"http://10.0.0.1:5002\"]"), Environment("Testing"));
        Assert.True(first.ContainsOrigin("HTTP://[FC00:0:0:0:0:0:0:1]:080"));
        Assert.False(second.ContainsOrigin("http://[fc00::1]:80"));
        Assert.True(second.ContainsOrigin("http://10.0.0.1:5002"));
        Assert.False(second.ContainsOrigin("http://10.0.0.1:5008"));
        Assert.False(second.ContainsOrigin("http://10.1:5002"));
    }

    [Fact]
    public async Task HttpPublicAuthority_MustBeListed_WhileHttpsNeedsNoHttpEntry()
    {
        var origins = "[\"http://10.0.0.1:80\"]";
        Assert.True(HostedLoginHttpTestPolicy.Create(await SnapshotAsync(origins, "http://10.0.0.1"), Environment("Testing")).Enabled);
        var unlisted = await SnapshotAsync(origins, "http://10.0.0.2:80");
        var error = Assert.Throws<InvalidOperationException>(() => HostedLoginHttpTestPolicy.Create(unlisted, Environment("Testing")));
        Assert.Equal("The HTTP public base URL authority must be in the shared hosted-login test origins.", error.Message);
    }

    [Fact]
    public void CompositeValidation_RejectsOversizedJsonDocument()
    {
        CompositeValidation_IsKeyScopedAndValueFree("[" + new string(' ', 8191) + "]");
    }

    [Theory]
    [InlineData("[\"http://127.0.0.1:80\"]")]
    [InlineData("[\"http://10.0.0.1:80\",\"http://10.0.0.1:80\"]")]
    public void CompositeValidation_IsKeyScopedAndValueFree(string json)
    {
        var values = InstallationTestSupport.BuildCompletedInstallationValues("policy_admin").ToDictionary(pair =>
            SharedSettingKeys.NormalizedByLegacyKey[pair.Key], pair => (string?)pair.Value);
        values[HostedLoginHttpTestOrigins.SettingKey] = json;
        var result = SharedSettingComposition.CreateRegistry(false).Validate(values);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Key == HostedLoginHttpTestOrigins.SettingKey
            && error.ErrorCode == HostedLoginHttpTestOrigins.InvalidCode);
    }

    [Theory]
    [InlineData("http://10.1:80")]
    [InlineData("http://167772161:80")]
    public async Task HttpPublicAuthority_CannotUseAnIpv4Alias(string url)
    {
        var snapshot = await SnapshotAsync("[\"http://10.0.0.1:80\"]", url);
        Assert.Throws<InvalidOperationException>(() => HostedLoginHttpTestPolicy.Create(snapshot, Environment("Testing")));
    }

    [Fact]
    public void CompleteCandidate_StillRequiresTheNewKey_AndIssuerRulesRemainIndependent()
    {
        var values = InstallationTestSupport.BuildCompletedInstallationValues("policy_admin").ToDictionary(pair => pair.Key, pair => pair.Value);
        values.Remove(SystemSettingKeys.SecurityHostedLoginHttpTestOrigins);
        Assert.Contains(SharedSettingComposition.ValidateCompleteCandidate(values), error =>
            error.Key == HostedLoginHttpTestOrigins.SettingKey && error.ErrorCode == SettingCandidateValidation.MissingCode);
        values[SystemSettingKeys.SecurityHostedLoginHttpTestOrigins] = "[\"http://10.0.0.1:80\"]";
        values[SystemSettingKeys.PublicBaseUrl] = "http://10.0.0.1";
        values[SystemSettingKeys.JwtIssuer] = "http://10.0.0.1";
        values[SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "false";
        Assert.Contains(SharedSettingComposition.ValidateCompleteCandidate(values), error =>
            error.ErrorCode == SignaCoreSettingCompositeValidator.HttpsRequiredCode);
        values[SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true";
        values[SystemSettingKeys.JwtIssuer] = "http://10.0.0.2";
        Assert.Contains(SharedSettingComposition.ValidateCompleteCandidate(values), error =>
            error.ErrorCode == SignaCoreSettingCompositeValidator.IssuerMismatchCode);
    }

    private static IHostEnvironment Environment(string name)
    {
        var mock = new Mock<IHostEnvironment>();
        mock.SetupGet(value => value.EnvironmentName).Returns(name);
        return mock.Object;
    }

    private static async Task<ServiceSettingSnapshot> SnapshotAsync(string? json, string url = "https://accounts.example.test")
    {
        var registry = SharedSettingComposition.CreateRegistry(false);
        var values = InstallationTestSupport.BuildCompletedInstallationValues("policy_admin").ToDictionary(pair =>
            SharedSettingKeys.NormalizedByLegacyKey[pair.Key], pair => pair.Value);
        values["endpoints.public_base_url"] = url;
        values["jwt.issuer"] = url;
        if (json is null) values.Remove(HostedLoginHttpTestOrigins.SettingKey);
        else values[HostedLoginHttpTestOrigins.SettingKey] = json;
        var service = ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier);
        var root = new MasterKeyRootKeySource(new BootstrapMasterKeyProvider("policy-tests-synthetic-root"));
        var key = await root.GetRootKeyAsync(TestContext.Current.CancellationToken);
        var read = new ServiceSettingSnapshotRead(service, 1, values.Select(pair =>
        {
            registry.TryGetDefinition(pair.Key, out var definition);
            return new PersistedServiceSettingValue(pair.Key, 1, definition!.ValueType, definition.IsSensitive
                ? new SensitiveValueProtector(service, pair.Key).Protect(pair.Value, key) : pair.Value);
        }));
        using var loader = new ServiceSettingSnapshotLoader(service, new FixedSource(read), registry,
            new ServiceSettingCurrentSnapshotAccessor(), root);
        var refresh = await loader.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.True(refresh.Succeeded);
        return refresh.Snapshot!;
    }
    private sealed class FixedSource(ServiceSettingSnapshotRead read) : IServiceSettingSnapshotSource
    {
        public ValueTask<ServiceSettingSnapshotRead> LoadAsync(ServiceId serviceId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(read);
    }
}
