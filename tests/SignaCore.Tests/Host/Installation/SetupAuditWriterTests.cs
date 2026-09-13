using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Host.Installation;

/// <summary>
/// The closed projection contract of <see cref="SetupAuditWriter"/>: exactly the fixed
/// installation-completed event shape is accepted, everything else is refused before anything is
/// staged, and the returned record shares the staged row's identifier.
/// </summary>
public sealed class SetupAuditWriterTests
{
    [Fact]
    public async Task RecordAsync_AcceptsTheFixedEvent_AndStagesTheLegacyRow()
    {
        await using var database = await TestDatabase.CreateAsync();
        var accountId = Guid.NewGuid();
        var occurredAt = DateTimeOffset.UtcNow;
        var auditEvent = CreateAcceptedEvent(accountId, occurredAt, clientIp: "192.0.2.10");
        var writer = new SetupAuditWriter(database.Context, "setup_admin");

        var record = await writer.RecordAsync(auditEvent, TestContext.Current.CancellationToken);

        var staged = Assert.Single(database.Context.AuditLogs.Local);
        Assert.Equal(staged.Id, record.Id);
        Assert.Equal("installation.setup.completed", staged.Action);
        Assert.Equal("Installation", staged.TargetType);
        Assert.Equal("signacore", staged.TargetId);
        Assert.Equal(accountId, staged.ActorId);
        Assert.Equal("setup_admin", staged.ActorName);
        Assert.Equal(auditEvent.SecurityDescription, staged.Description);
        Assert.Equal("192.0.2.10", staged.ClientIp);
        Assert.Null(staged.CorrelationId);
        Assert.Equal(occurredAt, staged.CreatedAt);
        // Deliberately no before/after snapshots: they would carry setting values.
        Assert.Null(staged.BeforeSnapshot);
        Assert.Null(staged.AfterSnapshot);

        // The record projects the shared event's own fields, not the legacy column names.
        Assert.Equal(auditEvent.Operator, record.Operator);
        Assert.Equal(auditEvent.Action, record.Action);
        Assert.Equal(auditEvent.Target, record.Target);
        Assert.Equal(ManagementAuditOutcome.Success, record.Outcome);
        Assert.Equal(occurredAt, record.OccurredAtUtc);
        Assert.Equal("192.0.2.10", record.ClientIp);
        Assert.Null(record.CorrelationId);
        Assert.Equal(auditEvent.SecurityDescription, record.SecurityDescription);
        Assert.Empty(record.Metadata);
    }

    public static TheoryData<string, ManagementAuditEvent> UnsupportedEvents()
    {
        var cases = new TheoryData<string, ManagementAuditEvent>();
        cases.Add(
            "different action",
            ManagementAuditEvent.Create(
                CreateOperator(Guid.NewGuid()),
                WellKnownManagementAuditActions.ConfigurationChanged,
                AcceptedTarget()));
        cases.Add(
            "different target type",
            ManagementAuditEvent.Create(
                CreateOperator(Guid.NewGuid()),
                WellKnownManagementAuditActions.InstallationCompleted,
                ManagementAuditTarget.Create(WellKnownManagementAuditTargetTypes.Configuration, "signacore")));
        cases.Add(
            "different target id",
            ManagementAuditEvent.Create(
                CreateOperator(Guid.NewGuid()),
                WellKnownManagementAuditActions.InstallationCompleted,
                ManagementAuditTarget.Create(WellKnownManagementAuditTargetTypes.Service, "another-service")));
        cases.Add(
            "failed outcome",
            ManagementAuditEvent.Create(
                CreateOperator(Guid.NewGuid()),
                WellKnownManagementAuditActions.InstallationCompleted,
                AcceptedTarget(),
                ManagementAuditOutcome.Failure));
        cases.Add(
            "different operator source",
            ManagementAuditEvent.Create(
                ManagementAuditOperator.Create(
                    WellKnownManagementAuditOperatorSources.System,
                    Guid.NewGuid().ToString("D")),
                WellKnownManagementAuditActions.InstallationCompleted,
                AcceptedTarget(),
                ManagementAuditOutcome.Success));
        cases.Add(
            "operator id is not a guid",
            ManagementAuditEvent.Create(
                ManagementAuditOperator.Create(SetupAuditWriter.OperatorSource, "not-a-guid"),
                WellKnownManagementAuditActions.InstallationCompleted,
                AcceptedTarget(),
                ManagementAuditOutcome.Success));
        cases.Add(
            "operator display name",
            ManagementAuditEvent.Create(
                ManagementAuditOperator.Create(
                    SetupAuditWriter.OperatorSource,
                    Guid.NewGuid().ToString("D"),
                    displayName: "setup_admin"),
                WellKnownManagementAuditActions.InstallationCompleted,
                AcceptedTarget(),
                ManagementAuditOutcome.Success));
        cases.Add(
            "metadata present",
            ManagementAuditEvent.Create(
                CreateOperator(Guid.NewGuid()),
                WellKnownManagementAuditActions.InstallationCompleted,
                AcceptedTarget(),
                ManagementAuditOutcome.Success,
                metadata: new Dictionary<string, string> { ["key"] = "value" }));
        return cases;
    }

    [Theory]
    [MemberData(nameof(UnsupportedEvents))]
    public async Task RecordAsync_RefusesUnsupportedShapes_BeforeStagingAnything(
        string caseName,
        ManagementAuditEvent auditEvent)
    {
        Assert.False(string.IsNullOrEmpty(caseName));
        await using var database = await TestDatabase.CreateAsync();
        var writer = new SetupAuditWriter(database.Context, "setup_admin");

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await writer.RecordAsync(auditEvent, TestContext.Current.CancellationToken));

        Assert.Empty(database.Context.AuditLogs.Local);
    }

    [Fact]
    public async Task RecordAsync_RejectsNullEvent()
    {
        await using var database = await TestDatabase.CreateAsync();
        var writer = new SetupAuditWriter(database.Context, "setup_admin");

        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await writer.RecordAsync(null!, TestContext.Current.CancellationToken));

        Assert.Empty(database.Context.AuditLogs.Local);
    }

    [Fact]
    public async Task RecordAsync_PreCanceledToken_StagesNothing()
    {
        await using var database = await TestDatabase.CreateAsync();
        var writer = new SetupAuditWriter(database.Context, "setup_admin");
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await writer.RecordAsync(
                CreateAcceptedEvent(Guid.NewGuid(), DateTimeOffset.UtcNow),
                cancellation.Token));

        Assert.Empty(database.Context.AuditLogs.Local);
    }

    internal static ManagementAuditEvent CreateAcceptedEvent(
        Guid accountId,
        DateTimeOffset occurredAt,
        string? clientIp = null) =>
        ManagementAuditEvent.Create(
            CreateOperator(accountId),
            WellKnownManagementAuditActions.InstallationCompleted,
            AcceptedTarget(),
            ManagementAuditOutcome.Success,
            occurredAtUtc: occurredAt,
            clientIp: clientIp,
            securityDescription: "First-run setup completed. ConfigurationVersion=1.");

    internal static ManagementAuditOperator CreateOperator(Guid accountId) =>
        ManagementAuditOperator.Create(SetupAuditWriter.OperatorSource, accountId.ToString("D"));

    internal static ManagementAuditTarget AcceptedTarget() =>
        ManagementAuditTarget.Create(WellKnownManagementAuditTargetTypes.Service, "signacore");

    internal sealed class TestDatabase : IAsyncDisposable
    {
        private TestDatabase(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        private SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public static async Task<TestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var context = new IdentityDbContext(
                new DbContextOptionsBuilder<IdentityDbContext>()
                    .UseSqlite(connection)
                    .Options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new TestDatabase(connection, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}
