using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Services;

public class RefreshTokenServiceTests
{
    private readonly Mock<IRefreshTokenRepository> _repoMock;
    private readonly Mock<IUnitOfWork> _unitOfWorkMock;
    private readonly RefreshTokenService _service;

    public RefreshTokenServiceTests()
    {
        _repoMock = new Mock<IRefreshTokenRepository>();
        _unitOfWorkMock = new Mock<IUnitOfWork>();
        _unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        _service = new RefreshTokenService(_repoMock.Object, _unitOfWorkMock.Object, new RefreshTokenOptions { RefreshTokenExpirationDays = 7 });
    }

    private static AccountEntity CreateAccount() => new()
    {
        Id = Guid.NewGuid(),
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    [Theory]
    [InlineData(IdentityConstants.GrantTypePassword)]
    [InlineData(IdentityConstants.GrantTypeSms)]
    [InlineData(IdentityConstants.GrantTypeWechat)]
    public async Task HandleRefreshTokenAsync_LoginGrants_GeneratesNewToken(string grantType)
    {
        var account = CreateAccount();

        var token = await _service.HandleRefreshTokenAsync(grantType, null, account, "app-1");

        Assert.NotNull(token);
        Assert.False(string.IsNullOrEmpty(token));
        _repoMock.Verify(r => r.AddAsync(It.Is<RefreshTokenEntity>(t =>
            t.AccountId == account.Id &&
            t.TokenValue == token &&
            !t.IsRevoked &&
            t.AppId == "app-1" &&
            t.ExpiresAt > DateTimeOffset.UtcNow.AddDays(6))), Times.Once);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_RefreshGrant_RevokesExistingThenGenerates()
    {
        var account = CreateAccount();
        var existing = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            TokenValue = "old-token",
            IsRevoked = false
        };
        _repoMock.Setup(r => r.GetByTokenValueAsync("old-token")).ReturnsAsync(existing);

        var token = await _service.HandleRefreshTokenAsync(
            IdentityConstants.GrantTypeRefreshToken, "old-token", account, null);

        Assert.NotNull(token);
        Assert.NotEqual("old-token", token);
        Assert.True(existing.IsRevoked);
        _repoMock.Verify(r => r.AddAsync(It.Is<RefreshTokenEntity>(t => t.TokenValue == token)), Times.Once);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_RefreshGrantWithoutToken_ReturnsNull()
    {
        var token = await _service.HandleRefreshTokenAsync(
            IdentityConstants.GrantTypeRefreshToken, null, CreateAccount(), null);

        Assert.Null(token);
        _repoMock.Verify(r => r.AddAsync(It.IsAny<RefreshTokenEntity>()), Times.Never);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_UnknownGrant_ReturnsNull()
    {
        var token = await _service.HandleRefreshTokenAsync("unknown-grant", "existing", CreateAccount(), null);

        Assert.Null(token);
        _repoMock.Verify(r => r.AddAsync(It.IsAny<RefreshTokenEntity>()), Times.Never);
    }

    [Fact]
    public async Task RevokeAsync_TokenFound_MarksRevokedAndSaves()
    {
        var entity = new RefreshTokenEntity { Id = Guid.NewGuid(), TokenValue = "t", IsRevoked = false };
        _repoMock.Setup(r => r.GetByTokenValueAsync("t")).ReturnsAsync(entity);

        var result = await _service.RevokeAsync("t");

        Assert.True(result);
        Assert.True(entity.IsRevoked);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RevokeAsync_TokenNotFound_ReturnsFalseWithoutSaving()
    {
        _repoMock.Setup(r => r.GetByTokenValueAsync("missing")).ReturnsAsync((RefreshTokenEntity?)null);

        var result = await _service.RevokeAsync("missing");

        Assert.False(result);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }
}
