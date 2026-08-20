using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
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
    public void RestartedProvider_UsesSharedDatabaseAndDoesNotPersistPlaintextXml()
    {
        var databaseName = $"data-protection-{Guid.NewGuid():N}";
        const string rootSecret = "data-protection-test-root-secret";
        const string plaintext = "admin-cookie-that-must-survive-a-restart";
        string protectedPayload;

        using (var firstProvider = CreateProvider(databaseName, rootSecret))
        {
            var protector = firstProvider.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("admin-cookie-test");
            protectedPayload = protector.Protect(plaintext);

            using var scope = firstProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var stored = Assert.Single(db.DataProtectionKeys);
            Assert.DoesNotContain(plaintext, stored.ProtectedXml, StringComparison.Ordinal);
            Assert.DoesNotContain("<key", stored.ProtectedXml, StringComparison.Ordinal);
        }

        using var restartedProvider = CreateProvider(databaseName, rootSecret);
        var restartedProtector = restartedProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("admin-cookie-test");

        Assert.Equal(plaintext, restartedProtector.Unprotect(protectedPayload));
    }

    private static ServiceProvider CreateProvider(string databaseName, string rootSecret)
    {
        var services = new ServiceCollection();
        services.AddDbContext<IdentityDbContext>(options => options.UseInMemoryDatabase(databaseName));
        services.AddSingleton<IConfigurationProtector>(new AesGcmConfigurationProtector(
            new BootstrapMasterKeyProvider(rootSecret)));
        services.AddSingleton<IXmlRepository, DatabaseDataProtectionKeyRepository>();
        services.AddSingleton<ConfigurationXmlEncryptor>();
        services.AddDataProtection().SetApplicationName("SignaCore.Admin.Tests");
        services.AddOptions<KeyManagementOptions>()
            .Configure<IXmlRepository, ConfigurationXmlEncryptor>((options, repository, encryptor) =>
            {
                options.XmlRepository = repository;
                options.XmlEncryptor = encryptor;
            });

        return services.BuildServiceProvider(validateScopes: true);
    }
}
