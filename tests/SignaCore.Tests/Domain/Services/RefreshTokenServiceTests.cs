using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class RefreshTokenServiceTests
{
    private readonly Mock<IRefreshTokenRepository> _repoMock;
    private readonly RefreshTokenService _service;

    public RefreshTokenServiceTests()
    {
        _repoMock = new Mock<IRefreshTokenRepository>();
        _service = new RefreshTokenService(
            _repoMock.Object,
            new RefreshTokenOptions { RefreshTokenExpirationDays = 7 });
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
    [InlineData(IdentityConstants.GrantTypeLdap)]
    public async Task HandleRefreshTokenAsync_LoginGrants_GeneratesNewToken(string grantType)
    {
        var account = CreateAccount();

        var token = await _service.HandleRefreshTokenAsync(grantType, null, account, "app-1");

        Assert.NotNull(token);
        Assert.False(string.IsNullOrEmpty(token));
        Assert.False(RefreshTokenDigest.IsDigest(token));
        _repoMock.Verify(r => r.AddAsync(It.Is<RefreshTokenEntity>(t =>
            t.AccountId == account.Id &&
            t.TokenValue == RefreshTokenDigest.Compute(token) &&
            !t.IsRevoked &&
            t.AppId == "app-1" &&
            t.ExpiresAt > DateTimeOffset.UtcNow.AddDays(6))), Times.Once);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_RefreshGrant_RevokesExistingThenGenerates()
    {
        var account = CreateAccount();
        _repoMock
            .Setup(r => r.TryRotateAsync("old-token", It.IsAny<RefreshTokenEntity>()))
            .ReturnsAsync(true);

        var token = await _service.HandleRefreshTokenAsync(
            IdentityConstants.GrantTypeRefreshToken, "old-token", account, "app-1");

        Assert.NotNull(token);
        Assert.NotEqual("old-token", token);
        _repoMock.Verify(
            r => r.TryRotateAsync(
                "old-token",
                It.Is<RefreshTokenEntity>(replacement =>
                    replacement.AccountId == account.Id &&
                    replacement.TokenValue == RefreshTokenDigest.Compute(token) &&
                    !replacement.IsRevoked &&
                    replacement.AppId == "app-1")),
            Times.Once);
        _repoMock.Verify(r => r.AddAsync(It.IsAny<RefreshTokenEntity>()), Times.Never);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_CrossApplicationExchange_MintsWithoutRevokingTheSourceToken()
    {
        // Rotation would revoke the presented token, and the presented token is the source
        // application's session credential — the user would be signed out there instead.
        var account = CreateAccount();

        var token = await _service.HandleRefreshTokenAsync(
            IdentityConstants.GrantTypeRefreshToken, "source-token", account, "target-app",
            exchangedFromAppId: "source-app");

        Assert.NotNull(token);
        _repoMock.Verify(r => r.TryRotateAsync(It.IsAny<string>(), It.IsAny<RefreshTokenEntity>()), Times.Never);
        _repoMock.Verify(r => r.AddAsync(It.Is<RefreshTokenEntity>(minted =>
            minted.AccountId == account.Id &&
            minted.AppId == "target-app" &&
            // Marks the token as already exchanged, so it cannot be exchanged a second time.
            minted.SourceAppId == "source-app" &&
            !minted.IsRevoked)), Times.Once);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_LdapGrant_BindsTokenToLdapCredential()
    {
        var account = CreateAccount();
        var credentialId = Guid.NewGuid();

        await _service.HandleRefreshTokenAsync(
            IdentityConstants.GrantTypeLdap,
            null,
            account,
            "app-1",
            credentialId);

        _repoMock.Verify(repository => repository.AddAsync(
            It.Is<RefreshTokenEntity>(token => token.LdapCredentialId == credentialId)), Times.Once);
    }

    [Fact]
    public async Task HandleRefreshTokenAsync_IssuingGrantWithoutAppId_Throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.HandleRefreshTokenAsync(
                IdentityConstants.GrantTypePassword, null, CreateAccount(), null));

        _repoMock.Verify(r => r.AddAsync(It.IsAny<RefreshTokenEntity>()), Times.Never);
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
    public async Task RevokeAsync_TokenFound_AtomicallyRevokes()
    {
        _repoMock.Setup(r => r.TryRevokeAsync("t")).ReturnsAsync(true);

        var result = await _service.RevokeAsync("t");

        Assert.True(result);
        _repoMock.Verify(r => r.TryRevokeAsync("t"), Times.Once);
    }

    [Fact]
    public async Task RevokeAsync_TokenNotFound_ReturnsFalseWithoutSaving()
    {
        _repoMock.Setup(r => r.TryRevokeAsync("missing")).ReturnsAsync(false);

        var result = await _service.RevokeAsync("missing");

        Assert.False(result);
    }
}
