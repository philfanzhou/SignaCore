using System.Security.Claims;
using ServiceMantle.Audit;
using ServiceMantle.Management;
using SignaCore.Host.Management;
using Xunit;

namespace SignaCore.Tests.Host.Management;

/// <summary>
/// The single SignaCore operator read point: the audit actor comes from the shared ServiceMantle
/// operator claims, and ordinary NameIdentifier/Name claims are never trusted as a fallback.
/// </summary>
public sealed class ManagementOperatorReaderTests
{
    private static readonly Guid OperatorId = Guid.NewGuid();

    private static ManagementOperatorReader CreateReader() => new(new ManagementCurrentOperatorResolver(
        new ManagementClaimsParser()));

    private static ClaimsPrincipal ManagementPrincipal(
        string operatorId,
        ManagementPermission[] permissions,
        string? displayName) =>
        ManagementIdentity.Create(
            WellKnownManagementAuditOperatorSources.InteractiveAdmin,
            operatorId,
            permissions,
            displayName).ToClaimsPrincipal();

    [Fact]
    public void Read_FromALegitimateManagementPrincipal_ReturnsTheOperatorIdAndDisplayName()
    {
        var reader = CreateReader();

        var (actorId, actorName) = reader.Read(ManagementPrincipal(
            OperatorId.ToString(),
            [ManagementPermission.Admin],
            "console-admin"));

        Assert.Equal(OperatorId, actorId);
        Assert.Equal("console-admin", actorName);
    }

    [Fact]
    public void Read_FromOrdinaryNameClaimsOnly_ReturnsNoActor()
    {
        var reader = CreateReader();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, OperatorId.ToString()),
            new Claim(ClaimTypes.Name, "console-admin")
        ], "Test"));

        var (actorId, actorName) = reader.Read(principal);

        // The exact values the legacy cookie used to carry are not a fallback source: a principal
        // that does not resolve through the shared claims parser yields no audit actor.
        Assert.Null(actorId);
        Assert.Null(actorName);
    }

    [Fact]
    public void Read_FromAManagementPrincipalWithoutADisplayName_ReturnsTheIdWithoutAName()
    {
        var reader = CreateReader();

        var (actorId, actorName) = reader.Read(ManagementPrincipal(
            OperatorId.ToString(),
            [ManagementPermission.Admin],
            displayName: null));

        Assert.Equal(OperatorId, actorId);
        Assert.Null(actorName);
    }

    [Fact]
    public void Read_FromAnUnparseableOperatorIdClaim_ReturnsNoActorId()
    {
        var reader = CreateReader();

        var (actorId, actorName) = reader.Read(ManagementPrincipal(
            "not-a-guid",
            [ManagementPermission.Admin],
            "console-admin"));

        Assert.Null(actorId);
        Assert.Equal("console-admin", actorName);
    }

    [Fact]
    public void Read_FromANullOrUnauthenticatedPrincipal_ReturnsNoActor()
    {
        var reader = CreateReader();

        Assert.Equal((null, null), reader.Read(null));
        Assert.Equal((null, null), reader.Read(new ClaimsPrincipal(new ClaimsIdentity())));
    }
}
