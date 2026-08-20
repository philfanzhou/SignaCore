using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host.Security;

public sealed class DatabaseDataProtectionKeyRepositoryTests
{
    [Fact]
    public void StoreAndRead_UsesSharedDatabaseAndDoesNotPersistPlaintextXml()
    {
        var databaseName = $"data-protection-{Guid.NewGuid():N}";
        var services = new ServiceCollection();
        services.AddDbContext<IdentityDbContext>(options => options.UseInMemoryDatabase(databaseName));
        services.AddSingleton<IConfigurationProtector>(new AesGcmConfigurationProtector(
            new BootstrapMasterKeyProvider("data-protection-test-root-secret")));
        services.AddSingleton<DatabaseDataProtectionKeyRepository>();

        using var provider = services.BuildServiceProvider();
        var repository = provider.GetRequiredService<DatabaseDataProtectionKeyRepository>();
        var encryptor = new ConfigurationXmlEncryptor(
            provider.GetRequiredService<IConfigurationProtector>());
        var element = XElement.Parse("<key id=\"shared-key\"><secret>not-plaintext</secret></key>");
        var encryptedElement = encryptor.Encrypt(element).EncryptedElement;

        repository.StoreElement(encryptedElement, "shared-key");

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var stored = Assert.Single(db.DataProtectionKeys);
            Assert.DoesNotContain("not-plaintext", stored.ProtectedXml, StringComparison.Ordinal);
        }

        var loaded = Assert.Single(repository.GetAllElements());
        Assert.True(XNode.DeepEquals(element, encryptor.Decrypt(loaded)));
    }
}
