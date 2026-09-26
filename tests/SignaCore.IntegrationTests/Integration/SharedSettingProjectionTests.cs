using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The shared setting query and update surface as composed by the real normal host: the empty
/// aggregate fails closed with the closed error classification, the definition projection is
/// stable and sorted, and after the first update the current-value projection distinguishes
/// Default / Missing / Persisted sources while sensitive values stay null.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class SharedSettingProjectionTests : IClassFixture<IdentityServerFixture>
{
    private static readonly ManagementAuditOperator Operator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.InteractiveAdmin,
        "projection-admin");

    private readonly IdentityServerFixture _fixture;

    public SharedSettingProjectionTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void Definitions_AreSortedAndCoverTheWholeDefinitionTable()
    {
        var service = _fixture.Services.GetRequiredService<ServiceSettingQueryService>();
        var definitions = service.GetDefinitions();

        Assert.Equal(44, definitions.Count);
        Assert.Equal(
            definitions.Select(definition => definition.Key).Order(StringComparer.Ordinal),
            definitions.Select(definition => definition.Key));
        Assert.Contains(definitions, definition =>
            definition.Key == "endpoints.public_base_url" && definition.IsRequired && !definition.HasDefault);
        Assert.Contains(definitions, definition =>
            definition.Key == "sms.otp_hmac_key" && definition.IsSensitive && !definition.IsRequired);
        Assert.All(definitions, definition => Assert.True(definition.RequiresRestart));
    }

    [Fact]
    public async Task EmptyAggregate_FailsClosedUntilTheFirstUpdateSeedsIt()
    {
        var service = _fixture.Services.GetRequiredService<ServiceSettingQueryService>();

        // 0. The host's startup migrated the legacy rows (#548); delete the aggregate row to
        //    recreate the empty-aggregate state the query contract has to fail closed on.
        using (var scope = _fixture.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>();
            await SharedSettingTestDatabase.DeleteAggregateAsync(
                context, TestContext.Current.CancellationToken);
        }

        // 1. The aggregate starts empty and the setup-collected keys are required without
        //    defaults, so the current-values query is not servable until the first update.
        var empty = await service.GetCurrentAsync(TestContext.Current.CancellationToken);
        Assert.False(empty.Succeeded);
        Assert.Null(empty.Version);
        Assert.Empty(empty.Values);
        Assert.All(empty.Errors, error =>
            Assert.Matches("^[a-z0-9][a-z0-9._-]*$", error.ErrorCode));

        // 2. Seed the aggregate once through the real composed update path. The process-local
        //    loader keeps the boot snapshot at version 1, and a same-version candidate with
        //    different content is a conflict by contract — so a second update advances the version
        //    before the query can serve the reseeded aggregate.
        using (var scope = _fixture.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>();
            await using var transaction = await context.Database.BeginTransactionAsync(
                TestContext.Current.CancellationToken);
            var update = scope.ServiceProvider.GetRequiredService<ServiceSettingUpdateService>();
            var seed = await update.UpdateAsync(
                new ServiceSettingUpdateCommand(0, SeedChanges(), Operator),
                TestContext.Current.CancellationToken);
            Assert.True(seed.Succeeded);
            Assert.Equal(1, seed.Version);
            var advance = await update.UpdateAsync(
                new ServiceSettingUpdateCommand(1, SeedChanges(), Operator),
                TestContext.Current.CancellationToken);
            Assert.True(advance.Succeeded);
            Assert.Equal(2, advance.Version);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        // 3. The seeded aggregate projects Default / Missing / Persisted and keeps sensitive
        //    values behind the boundary.
        var seeded = await service.GetCurrentAsync(TestContext.Current.CancellationToken);
        Assert.True(seeded.Succeeded);
        Assert.Equal(2, seeded.Version);
        var byKey = seeded.Values.ToDictionary(value => value.Key, StringComparer.Ordinal);

        var baseUrl = byKey["endpoints.public_base_url"];
        Assert.True(baseUrl.HasValue);
        Assert.Equal(ServiceSettingValueSource.Persisted, baseUrl.Source);
        Assert.Equal("https://projection.example.com", baseUrl.Value);

        var audience = byKey["jwt.audience"];
        Assert.True(audience.HasValue);
        Assert.Equal(ServiceSettingValueSource.Default, audience.Source);
        Assert.Equal("SignaCore.Services", audience.Value);

        var lokiUri = byKey["loki.uri"];
        Assert.False(lokiUri.HasValue);
        Assert.Equal(ServiceSettingValueSource.Missing, lokiUri.Source);
        Assert.Null(lokiUri.Value);

        var hmacKey = byKey["sms.otp_hmac_key"];
        Assert.True(hmacKey.IsSensitive);
        Assert.True(hmacKey.HasValue);
        Assert.Null(hmacKey.Value);
    }

    private static Dictionary<string, string?> SeedChanges() => new()
    {
        ["endpoints.public_base_url"] = "https://projection.example.com",
        ["jwt.issuer"] = "https://projection.example.com",
        ["admin.username"] = "projection-admin",
        ["sms.otp_hmac_key"] = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
    };
}
