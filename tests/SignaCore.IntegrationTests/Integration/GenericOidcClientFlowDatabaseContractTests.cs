using Xunit;

namespace SignaCore.Tests.Integration;

public sealed class GenericOidcClientFlowDatabaseContractTests
{
    [Fact]
    public async Task TheGenericHandler_CompletesSignInWithLongStateAndNonce_OnPostgreSql()
    {
        await using var database = await OidcDatabaseTestSupport.Harness.CreateAsync();
        using var identity = database.CreateHost();

        await GenericOidcClientFlowTests.CompleteSignInAndSignOutAsync(identity.Factory, nonceLength: 130);
    }
}
