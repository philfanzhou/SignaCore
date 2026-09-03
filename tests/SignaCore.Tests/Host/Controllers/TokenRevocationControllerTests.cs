using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using Moq;
using SignaCore.Domain.Services;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class TokenRevocationControllerTests
{
    private readonly Mock<IRefreshTokenService> _refreshTokenServiceMock = AuthTestDoubles.RefreshTokenService();

    private TokenRevocationController CreateController() =>
        new TokenRevocationController(
            _refreshTokenServiceMock.Object,
            NullLogger<TokenRevocationController>.Instance)
            .WithHttpContext();

    [Fact]
    public async Task RevokeRefreshToken_WithEmptyToken_ReturnsFailure()
    {
        var controller = CreateController();

        var request = new RevokeRequest { RefreshToken = "" };

        var actionResult = await controller.RevokeRefreshToken(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RevokeResponse>(ok.Value!);
        Assert.False(response.Success);

        _refreshTokenServiceMock.Verify(s => s.RevokeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RevokeRefreshToken_TokenFound_ReturnsTrue()
    {
        _refreshTokenServiceMock.Setup(s => s.RevokeAsync("rt-1", TestContext.Current.CancellationToken)).ReturnsAsync(true);
        var controller = CreateController();

        var actionResult = await controller.RevokeRefreshToken(new RevokeRequest { RefreshToken = "rt-1" }, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        Assert.True(Assert.IsType<RevokeResponse>(ok.Value!).Success);
    }

    [Fact]
    public async Task RevokeRefreshToken_TokenMissing_ReturnsFalse()
    {
        _refreshTokenServiceMock.Setup(s => s.RevokeAsync("missing", TestContext.Current.CancellationToken)).ReturnsAsync(false);
        var controller = CreateController();

        var actionResult = await controller.RevokeRefreshToken(new RevokeRequest { RefreshToken = "missing" }, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        Assert.False(Assert.IsType<RevokeResponse>(ok.Value!).Success);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RevokeRefreshToken_ForwardsActionTokenToRepositoryAndReturnsItsResult(bool revoked)
    {
        using var cancellation = new CancellationTokenSource();
        var repository = new Mock<IRefreshTokenRepository>(MockBehavior.Strict);
        repository.Setup(value => value.TryRevokeAsync("unused-token", cancellation.Token))
            .ReturnsAsync(revoked);
        var controller = CreateController(repository.Object);

        var result = await controller.RevokeRefreshToken(
            new RevokeRequest { RefreshToken = "unused-token" }, cancellation.Token);

        Assert.Equal(revoked, Assert.IsType<RevokeResponse>(AuthTestDoubles.ExtractOk(result).Value).Success);
        repository.Verify(value => value.TryRevokeAsync("unused-token", cancellation.Token), Times.Once);
        repository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RevokeRefreshToken_WhenRepositoryObservesCancellation_DoesNotReturnSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var repository = new Mock<IRefreshTokenRepository>(MockBehavior.Strict);
        repository.Setup(value => value.TryRevokeAsync("unused-token", cancellation.Token))
            .Returns(Task.FromCanceled<bool>(cancellation.Token));
        var controller = CreateController(repository.Object);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.RevokeRefreshToken(
            new RevokeRequest { RefreshToken = "unused-token" }, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        repository.Verify(value => value.TryRevokeAsync("unused-token", cancellation.Token), Times.Once);
        repository.VerifyNoOtherCalls();
    }

    private static TokenRevocationController CreateController(IRefreshTokenRepository repository) =>
        new TokenRevocationController(
            new RefreshTokenService(repository, new RefreshTokenOptions()),
            NullLogger<TokenRevocationController>.Instance).WithHttpContext();
}
