namespace SignaCore.Domain.Services.Ldap;

public sealed class LdapOptions
{
    public const string SectionName = "Ldap";

    public bool Enabled { get; set; }
    public string DefaultDirectoryKey { get; set; } = string.Empty;
    public int MaxConcurrentOperations { get; set; } = 20;
    public List<LdapDirectoryOptions> Directories { get; set; } = [];

    public void Validate()
    {
        if (!Enabled)
        {
            return;
        }

        if (Directories.Count == 0)
        {
            throw new InvalidOperationException("Ldap:Directories must contain at least one directory when LDAP is enabled.");
        }

        if (MaxConcurrentOperations is < 1 or > 200)
        {
            throw new InvalidOperationException("Ldap:MaxConcurrentOperations must be between 1 and 200.");
        }

        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var directory in Directories)
        {
            directory.Validate();
            if (!keys.Add(directory.Key))
            {
                throw new InvalidOperationException($"Duplicate LDAP directory key: {directory.Key}");
            }
        }

        if (string.IsNullOrWhiteSpace(DefaultDirectoryKey) ||
            !keys.Contains(DefaultDirectoryKey))
        {
            throw new InvalidOperationException("Ldap:DefaultDirectoryKey must reference a configured directory.");
        }
    }
}

public sealed class LdapDirectoryOptions
{
    public string Key { get; set; } = string.Empty;
    public List<string> Hosts { get; set; } = [];
    public int Port { get; set; } = 636;
    public string BaseDn { get; set; } = string.Empty;
    public string BindUsername { get; set; } = string.Empty;
    public string BindPassword { get; set; } = string.Empty;
    public List<string> UpnSuffixes { get; set; } = [];
    public List<string> NetbiosNames { get; set; } = [];
    public int TimeoutSeconds { get; set; } = 5;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Key) || Hosts.Count == 0 ||
            Hosts.Any(string.IsNullOrWhiteSpace) || string.IsNullOrWhiteSpace(BaseDn) ||
            string.IsNullOrWhiteSpace(BindUsername) || string.IsNullOrWhiteSpace(BindPassword))
        {
            throw new InvalidOperationException($"LDAP directory '{Key}' is incomplete.");
        }

        if (Port is < 1 or > 65535 || TimeoutSeconds is < 1 or > 60)
        {
            throw new InvalidOperationException($"LDAP directory '{Key}' has an invalid port or timeout.");
        }
    }
}
