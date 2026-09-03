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

    [Theory]
    [InlineData("password", false)]
    [InlineData("sms", false)]
    [InlineData("wechat_code", false)]
    [InlineData("ldap", false)]
    [InlineData("refresh_token", false)]
    [InlineData("refresh_token", true)]
    public async Task HandleRefreshToken_ForwardsCancellationAndPreservesOutcome(string grant, bool exchange)
    {
        using var cancellation = new CancellationTokenSource();
        var rotates = grant == "refresh_token" && !exchange;
        _repoMock.Setup(repository => repository.TryRotateAsync(
                It.IsAny<string>(), It.IsAny<RefreshTokenEntity>(), cancellation.Token)).ReturnsAsync(true);

        var result = await _service.HandleRefreshTokenAsync(grant, "unused-source", CreateAccount(), "app-1",
            exchangedFromAppId: exchange ? "source-app" : null, cancellationToken: cancellation.Token);

        Assert.False(string.IsNullOrEmpty(result));
        _repoMock.Verify(repository => repository.AddAsync(It.IsAny<RefreshTokenEntity>(), cancellation.Token),
            rotates ? Times.Never() : Times.Once());
        _repoMock.Verify(repository => repository.TryRotateAsync(
            It.IsAny<string>(), It.IsAny<RefreshTokenEntity>(), cancellation.Token),
            rotates ? Times.Once() : Times.Never());
        _repoMock.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("password", false)]
    [InlineData("sms", false)]
    [InlineData("wechat_code", false)]
    [InlineData("ldap", false)]
    [InlineData("refresh_token", false)]
    [InlineData("refresh_token", true)]
    public async Task HandleRefreshToken_WhenStorageCancels_DoesNotReturnToken(string grant, bool exchange)
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        _repoMock.Setup(repository => repository.AddAsync(It.IsAny<RefreshTokenEntity>(), cancellation.Token))
            .Returns(Task.FromCanceled(cancellation.Token));
        _repoMock.Setup(repository => repository.TryRotateAsync(
                It.IsAny<string>(), It.IsAny<RefreshTokenEntity>(), cancellation.Token))
            .Returns(Task.FromCanceled<bool>(cancellation.Token));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.HandleRefreshTokenAsync(grant, "unused-source", CreateAccount(), "app-1",
                exchangedFromAppId: exchange ? "source-app" : null, cancellationToken: cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Single(_repoMock.Invocations);
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

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Revoke_ForwardsCancellationAndPreservesRepositoryResult(bool appScoped, bool revoked)
    {
        using var cancellation = new CancellationTokenSource();
        _repoMock.Setup(repository => repository.TryRevokeAsync("unused-token", cancellation.Token))
            .ReturnsAsync(revoked);
        _repoMock.Setup(repository => repository.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token))
            .ReturnsAsync(revoked);

        var result = appScoped
            ? await _service.RevokeForAppAsync("unused-token", "app-1", cancellation.Token)
            : await _service.RevokeAsync("unused-token", cancellation.Token);

        Assert.Equal(revoked, result);
        _repoMock.Verify(repository => repository.TryRevokeAsync("unused-token", cancellation.Token),
            appScoped ? Times.Never() : Times.Once());
        _repoMock.Verify(repository => repository.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token),
            appScoped ? Times.Once() : Times.Never());
        _repoMock.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Revoke_WhenRepositoryObservesCancellation_PropagatesException(bool appScoped)
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        _repoMock.Setup(repository => repository.TryRevokeAsync("unused-token", cancellation.Token))
            .Returns(Task.FromCanceled<bool>(cancellation.Token));
        _repoMock.Setup(repository => repository.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token))
            .Returns(Task.FromCanceled<bool>(cancellation.Token));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => appScoped
            ? _service.RevokeForAppAsync("unused-token", "app-1", cancellation.Token)
            : _service.RevokeAsync("unused-token", cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        _repoMock.Verify(repository => repository.TryRevokeAsync("unused-token", cancellation.Token),
            appScoped ? Times.Never() : Times.Once());
        _repoMock.Verify(repository => repository.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token),
            appScoped ? Times.Once() : Times.Never());
        _repoMock.VerifyNoOtherCalls();
    }
}
