using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;
using SignaCore.Host.Controllers;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class OAuthTokenRevocationControllerTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Revoke_ForwardsActionTokenToRepositoryWithoutDisclosingResult(bool revoked)
    {
        using var cancellation = new CancellationTokenSource();
        var repository = new Mock<IRefreshTokenRepository>(MockBehavior.Strict);
        repository.Setup(value => value.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token))
            .ReturnsAsync(revoked);
        var controller = CreateController(repository.Object);

        var result = await controller.Revoke(cancellation.Token);

        Assert.IsType<OkResult>(result);
        repository.Verify(value => value.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token), Times.Once);
        repository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Revoke_WhenRepositoryObservesCancellation_DoesNotReturnSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var repository = new Mock<IRefreshTokenRepository>(MockBehavior.Strict);
        repository.Setup(value => value.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token))
            .Returns(Task.FromCanceled<bool>(cancellation.Token));
        var controller = CreateController(repository.Object);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.Revoke(cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        repository.Verify(value => value.TryRevokeForAppAsync("unused-token", "app-1", cancellation.Token), Times.Once);
        repository.VerifyNoOtherCalls();
    }

    private static OAuthTokenController CreateController(IRefreshTokenRepository repository)
    {
        // Revocation does not use the token issuance service.
        var controller = new OAuthTokenController(
            null!, new RefreshTokenService(repository, new RefreshTokenOptions())).WithHttpContext();
        controller.HttpContext.Items[IdentityHeaders.ValidatedApp] = new AppRegistrationEntity { AppId = "app-1" };
        controller.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["token"] = "unused-token",
            ["token_type_hint"] = "refresh_token"
        });
        return controller;
    }
}
