using Moq;
using ServiceMantle.Audit;
using SignaCore.Host.Audit;
using Xunit;

namespace SignaCore.Tests.Host.Audit;

/// <summary>
/// The new action-audit contract: the legacy call shape is projected onto the shared
/// <see cref="ManagementAuditEvent"/> model and staged through the shared writer, which
/// participates in the caller's unit of work. These tests replace the deleted
/// <c>AuditServiceTests.RecordActionAsync_*</c> set; the mapping is the new equivalent of
/// <c>RecordActionAsync_SavesAuditLog</c>.
/// </summary>
public sealed class ManagementActionAuditTests
{
    private sealed class RecordingWriter : IManagementAuditWriter
    {
        public List<ManagementAuditEvent> Events { get; } = [];

        public ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add(auditEvent);
            return ValueTask.FromResult(new ManagementAuditRecord(
                Guid.NewGuid(),
                auditEvent.Operator,
                auditEvent.Action,
                auditEvent.Target,
                auditEvent.Outcome,
                auditEvent.OccurredAtUtc,
                auditEvent.ClientIp,
                auditEvent.CorrelationId,
                auditEvent.SecurityDescription,
                auditEvent.Metadata));
        }
    }

    [Fact]
    public async Task RecordAsync_StagesTheSharedEventWithTheMappedFields()
    {
        var writer = new RecordingWriter();
        var actorId = Guid.NewGuid();

        await ManagementActionAudit.RecordAsync(
            writer,
            ManagementActionAudit.AdminSource,
            "account_created", "Account", "123",
            actorId, "admin", "Created account",
            "127.0.0.1", "correlation-1",
            cancellationToken: TestContext.Current.CancellationToken);

        var auditEvent = Assert.Single(writer.Events);
        Assert.Equal("interactive_admin", auditEvent.Operator.Source.Value);
        Assert.Equal(actorId.ToString("D"), auditEvent.Operator.OperatorId);
        Assert.Equal("admin", auditEvent.Operator.DisplayName);
        Assert.Equal("account_created", auditEvent.Action.Value);
        Assert.Equal("account", auditEvent.Target.Type.Value);
        Assert.Equal("123", auditEvent.Target.Id);
        Assert.Equal(ManagementAuditOutcome.Success, auditEvent.Outcome);
        Assert.Equal("127.0.0.1", auditEvent.ClientIp);
        Assert.Equal("correlation-1", auditEvent.CorrelationId);
        Assert.Equal("Created account", auditEvent.SecurityDescription);
    }

    [Fact]
    public async Task RecordAsync_NormalizesTargetTypesAndPassesTheOutcomeThrough()
    {
        var writer = new RecordingWriter();

        await ManagementActionAudit.RecordAsync(
            writer,
            ManagementActionAudit.SystemSource,
            "oidc.authorize.validated", "OidcAuthorizationRequest", "d0aa69b1-0000-0000-0000-000000000000",
            actorId: null, actorName: "bootstrap", description: "accepted",
            clientIp: null,
            outcome: ManagementAuditOutcome.Denied,
            cancellationToken: TestContext.Current.CancellationToken);

        var auditEvent = Assert.Single(writer.Events);
        Assert.Equal("system", auditEvent.Operator.Source.Value);
        Assert.Null(auditEvent.Operator.OperatorId);
        Assert.Equal("bootstrap", auditEvent.Operator.DisplayName);
        Assert.Equal("oidcauthorizationrequest", auditEvent.Target.Type.Value);
        Assert.Equal(ManagementAuditOutcome.Denied, auditEvent.Outcome);
        Assert.Null(auditEvent.ClientIp);
    }

    [Fact]
    public async Task RecordAsync_WithUnparseableForwardedClientIp_StagesWithoutClientIp()
    {
        // A forwarded header can carry any text. The shared model only accepts a real address, so
        // attribution degrades to null instead of failing the business action.
        var writer = new RecordingWriter();

        await ManagementActionAudit.RecordAsync(
            writer,
            ManagementActionAudit.AccountSource,
            "password_changed", "Account", "123",
            Guid.NewGuid(), null, "User changed password",
            clientIp: "not-an-ip, definitely spoofed",
            cancellationToken: TestContext.Current.CancellationToken);

        var auditEvent = Assert.Single(writer.Events);
        Assert.Null(auditEvent.ClientIp);
    }

    /// <summary>
    /// The deliberate behavior change of this switch: an audit refusal propagates instead of being
    /// swallowed, so the caller's transaction rolls back. This is the new-contract rewrite of the
    /// old <c>RecordActionAsync_WhenRepositoryThrows_DoesNotPropagateException</c>.
    /// </summary>
    [Fact]
    public async Task RecordAsync_WhenTheWriterRefuses_PropagatesInsteadOfSwallowing()
    {
        var writer = new Mock<IManagementAuditWriter>();
        writer
            .Setup(w => w.RecordAsync(It.IsAny<ManagementAuditEvent>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ManagementAuditException(
                "audit.description_invalid",
                "The audit security description exceeds the maximum allowed length."));

        await Assert.ThrowsAsync<ManagementAuditException>(() => ManagementActionAudit.RecordAsync(
            writer.Object,
            ManagementActionAudit.AdminSource,
            "account_created", "Account", "123",
            Guid.NewGuid(), "admin",
            description: new string('x', ManagementAuditEvent.MaxDescriptionLength + 1),
            cancellationToken: TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task RecordAsync_WithPreCanceledToken_PropagatesWithoutStaging()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var writer = new RecordingWriter();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ManagementActionAudit.RecordAsync(
            writer,
            ManagementActionAudit.AdminSource,
            "account_created", "Account", "123",
            Guid.NewGuid(), "admin", "Created account",
            cancellationToken: cancellation.Token).AsTask());

        Assert.Empty(writer.Events);
    }
}
