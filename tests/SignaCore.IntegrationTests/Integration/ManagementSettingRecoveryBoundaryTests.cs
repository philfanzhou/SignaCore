using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using ServiceMantle.Persistence.Relational.Stores;
using SignaCore.Host.Installation;
using SignaCore.Host.Management;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed partial class ManagementSettingRecoveryDatabaseContractTests
{
    [Theory]
    [InlineData(false, "unknown")]
    [InlineData(false, "decrypt")]
    [InlineData(false, "critical")]
    [InlineData(false, "type")]
    [InlineData(true, "unknown")]
    [InlineData(true, "decrypt")]
    [InlineData(true, "critical")]
    [InlineData(true, "type")]
    public async Task CorruptBaseline_FailsClosedWithNoWritesOrPartialQuery(bool postgres, string kind)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var audits = (await fixture.AuditsAsync()).Count;
        var values = SharedSettingTestDatabase.ParseValues(before);
        values[kind switch
        {
            "unknown" => "unknown.persisted.key", "decrypt" => "loki.authorization",
            "critical" => "jwt.issuer", _ => "jwt.token_expiration_hours"
        }] = kind switch
        {
            "decrypt" => "sm:v1:invalid-ciphertext", "critical" => "https://other.example.com", _ => "invalid"
        };
        await using (var context = fixture.Context())
            await context.Database.ExecuteSqlAsync(
                $"UPDATE service_settings SET values_json = {JsonSerializer.Serialize(values)} WHERE service_id = 'signacore'",
                TestContext.Current.CancellationToken);
        foreach (var path in new[] { Root, Root + "?group=loki" })
        {
            using var query = await admin.GetAsync(path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, query.StatusCode);
            Assert.Equal("{\"errorCode\":\"management.settings.unavailable\"}",
                await query.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        using var rejected = await PostAsync(admin, before.Version, new() { ["jwt.audience"] = "valid-audience" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, rejected.StatusCode);
        Assert.Equal("{\"errorCode\":\"management.settings.update_unavailable\"}",
            await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        // Version conflict wins before baseline materialization, even if the stored baseline is damaged.
        using var stale = await PostAsync(admin, before.Version - 1, new() { ["jwt.audience"] = "valid-audience" });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal(before.Version, (await fixture.StoredAsync()).Version);
        Assert.Equal(audits, (await fixture.AuditsAsync()).Count);
    }

    [Theory]
    [InlineData(false, "load")]
    [InlineData(false, "materialize")]
    [InlineData(false, "candidate")]
    [InlineData(false, "apply")]
    [InlineData(false, "commit")]
    [InlineData(true, "load")]
    [InlineData(true, "materialize")]
    [InlineData(true, "candidate")]
    [InlineData(true, "apply")]
    [InlineData(true, "commit")]
    public async Task RecoveryCancellation_PreservesTokenAndRollsBackWholeAttempt(bool postgres, string boundary)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        var rootKey = factory.Services.GetRequiredService<IServiceSettingRootKeySource>();
        var before = await fixture.StoredAsync();
        var audits = (await fixture.AuditsAsync()).Count;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        await using (var context = fixture.ContextWithoutRetry())
        await using (var transaction = await context.Database.BeginTransactionAsync(
            System.Data.IsolationLevel.Serializable, cancellation.Token))
        {
            var inner = new CancellationTransaction(
                new EfCoreServiceSettingUpdateTransaction<SignaCore.Database.IdentityDbContext>(context),
                cancellation, boundary);
            var keySource = new CancellationRootKey(
                rootKey, cancellation, boundary);
            var command = new ServiceSettingUpdateCommand(before.Version,
                new Dictionary<string, string?> { ["jwt.audience"] = "valid-audience" },
                ManagementAuditOperator.Create(WellKnownManagementAuditOperatorSources.InteractiveAdmin, "recovery-test"));
            var recovery = new ManagementSettingRecovery(inner, keySource, false, command);
            var service = new ServiceSettingUpdateService(InstallationStores.ServiceId, recovery.Registry, recovery, keySource);
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                var result = await service.UpdateAsync(command, cancellation.Token);
                Assert.True(result.Succeeded);
                if (boundary == "commit") await cancellation.CancelAsync();
                await transaction.CommitAsync(cancellation.Token);
            });
            Assert.Equal(cancellation.Token, error.CancellationToken);
            Assert.Equal(1, inner.LoadCount);
            Assert.Equal(boundary is "apply" or "commit" ? 1 : 0, inner.ApplyCount);
            await transaction.RollbackAsync(CancellationToken.None);
        }
        var after = await fixture.StoredAsync();
        Assert.Equal(before.Version, after.Version);
        Assert.Equal(before.ValuesJson, after.ValuesJson);
        Assert.Equal(audits, (await fixture.AuditsAsync()).Count);
    }

    private sealed class CancellationRootKey(IServiceSettingRootKeySource inner,
        CancellationTokenSource cancellation, string boundary) : IServiceSettingRootKeySource
    {
        private int calls;
        public async ValueTask<string> GetRootKeyAsync(CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            var key = await inner.GetRootKeyAsync(cancellationToken);
            if (++calls == (boundary == "candidate" ? 2 : 1) && boundary is "materialize" or "candidate")
                await cancellation.CancelAsync();
            return key;
        }
    }

    private sealed class CancellationTransaction(IServiceSettingUpdateTransaction inner,
        CancellationTokenSource cancellation, string boundary) : IServiceSettingUpdateTransaction
    {
        internal int LoadCount, ApplyCount;
        public async ValueTask<ServiceSettingStoreSnapshot> LoadAsync(ServiceId serviceId, CancellationToken token)
        {
            Assert.Equal(cancellation.Token, token);
            LoadCount++;
            var snapshot = await inner.LoadAsync(serviceId, token);
            if (boundary == "load") await cancellation.CancelAsync();
            return snapshot;
        }

        public async ValueTask<ServiceSettingUpdateResult> ApplyAsync(ServiceId serviceId,
            ServiceSettingStoreUpdate update, IReadOnlyList<ManagementAuditEvent> audits, CancellationToken token)
        {
            Assert.Equal(cancellation.Token, token);
            ApplyCount++;
            var result = await inner.ApplyAsync(serviceId, update, audits, token);
            if (boundary == "apply") await cancellation.CancelAsync();
            return result;
        }
    }
}
