using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Host.Controllers;
using QuantumZhou.Identity.Host.Models;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Controllers;

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

        var actionResult = await controller.RevokeRefreshToken(request);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RevokeResponse>(ok.Value!);
        Assert.False(response.Success);

        _refreshTokenServiceMock.Verify(s => s.RevokeAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RevokeRefreshToken_TokenFound_ReturnsTrue()
    {
        _refreshTokenServiceMock.Setup(s => s.RevokeAsync("rt-1")).ReturnsAsync(true);
        var controller = CreateController();

        var actionResult = await controller.RevokeRefreshToken(new RevokeRequest { RefreshToken = "rt-1" });

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        Assert.True(Assert.IsType<RevokeResponse>(ok.Value!).Success);
    }

    [Fact]
    public async Task RevokeRefreshToken_TokenMissing_ReturnsFalse()
    {
        _refreshTokenServiceMock.Setup(s => s.RevokeAsync("missing")).ReturnsAsync(false);
        var controller = CreateController();

        var actionResult = await controller.RevokeRefreshToken(new RevokeRequest { RefreshToken = "missing" });

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        Assert.False(Assert.IsType<RevokeResponse>(ok.Value!).Success);
    }
}
