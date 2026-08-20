using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Security;

/// <summary>
/// Persists the administrative cookie key ring in the shared identity database. The XML is
/// protected before storage with the same external root secret used for other encrypted deployment
/// configuration, under a separate authenticated-data name per key.
/// </summary>
internal sealed class DatabaseDataProtectionKeyRepository : IXmlRepository
{
    private const string ProtectionKeyPrefix = "DataProtection:";

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IConfigurationProtector _protector;

    public DatabaseDataProtectionKeyRepository(
        IServiceScopeFactory scopeFactory,
        IConfigurationProtector protector)
    {
        _scopeFactory = scopeFactory;
        _protector = protector;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return db.DataProtectionKeys
            .AsNoTracking()
            .OrderBy(key => key.FriendlyName)
            .Select(key => new { key.FriendlyName, key.ProtectedXml })
            .AsEnumerable()
            .Select(key => XElement.Parse(
                _protector.Unprotect(ProtectionKeyPrefix + key.FriendlyName, key.ProtectedXml),
                LoadOptions.PreserveWhitespace))
            .ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        ArgumentException.ThrowIfNullOrWhiteSpace(friendlyName);

        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        db.DataProtectionKeys.Add(new DataProtectionKeyEntity
        {
            Id = Guid.NewGuid(),
            FriendlyName = friendlyName,
            ProtectedXml = _protector.Protect(
                ProtectionKeyPrefix + friendlyName,
                element.ToString(SaveOptions.DisableFormatting))
        });
        db.SaveChanges();
    }
}
