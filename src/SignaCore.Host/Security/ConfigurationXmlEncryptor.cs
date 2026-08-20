using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Security;

/// <summary>
/// Marks the Data Protection key ring as encrypted using the deployment root key. This is the
/// framework-visible encryption layer; the database repository additionally protects its complete
/// stored payload and binds it to the row's friendly name.
/// </summary>
public sealed class ConfigurationXmlEncryptor : IXmlEncryptor, IXmlDecryptor
{
    private const string ProtectionKey = "DataProtection:KeyXml";

    private readonly IConfigurationProtector _protector;

    public ConfigurationXmlEncryptor(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _protector = services.GetRequiredService<IConfigurationProtector>();
    }

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);
        var protectedValue = _protector.Protect(
            ProtectionKey,
            plaintextElement.ToString(SaveOptions.DisableFormatting));
        return new EncryptedXmlInfo(
            new XElement("protectedKey", new XAttribute("value", protectedValue)),
            typeof(ConfigurationXmlEncryptor));
    }

    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);
        var protectedValue = encryptedElement.Attribute("value")?.Value;
        if (string.IsNullOrWhiteSpace(protectedValue))
        {
            throw new CryptographicException("The protected Data Protection key XML is malformed.");
        }

        return XElement.Parse(
            _protector.Unprotect(ProtectionKey, protectedValue),
            LoadOptions.PreserveWhitespace);
    }
}
