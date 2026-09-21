using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Host;

public sealed class OAuthLogoutCancellationTests
{
    [Theory]
    [InlineData("entry")]
    [InlineData("cached-form")]
    [InlineData("dispatch")]
    public async Task Prepare_ObservesTheOriginalCallerBeforeAnyBusinessWork(string boundary)
    {
        using var caller = new CancellationTokenSource();
        var context = new DefaultHttpContext { RequestAborted = caller.Token };
        context.Items[IdentityHeaders.ValidatedApp] = new AppRegistrationEntity { AppId = "probe" };
        var form = new Mock<IFormCollection>();
        IEnumerable<KeyValuePair<string, StringValues>> Fields()
        {
            if (boundary == "dispatch") caller.Cancel();
            yield return new("id_token_hint", "synthetic-hint");
        }
        form.Setup(value => value.GetEnumerator()).Returns(() => Fields().GetEnumerator());
        var feature = new Mock<IFormFeature>();
        feature.SetupGet(value => value.Form).Returns(() =>
        {
            if (boundary == "cached-form") caller.Cancel();
            return form.Object;
        });
        context.Features.Set(feature.Object);
        if (boundary == "entry") caller.Cancel();
        // No dependencies may be reached: a missing observation would fail instead of canceling.
        var controller = new OAuthLogoutController(null!, null!, null!, null!, null!)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => controller.Prepare(caller.Token));
        Assert.Equal(caller.Token, error.CancellationToken);
        feature.Verify(value => value.ReadFormAsync(It.IsAny<CancellationToken>()), Times.Never());
    }
}
