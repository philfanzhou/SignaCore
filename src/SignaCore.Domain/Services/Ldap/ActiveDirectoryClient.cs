using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace SignaCore.Domain.Services.Ldap;

public sealed class ActiveDirectoryClient : ILdapDirectoryClient, IDisposable
{
    private const int LdapInvalidCredentialsErrorCode = 49;
    private readonly LdapOptions _options;
    private readonly SemaphoreSlim _operations;

    public ActiveDirectoryClient(LdapOptions options)
    {
        _options = options;
        _operations = new SemaphoreSlim(options.MaxConcurrentOperations, options.MaxConcurrentOperations);
    }

    public LdapDirectoryOptions ResolveDirectory(string username)
    {
        var value = username.Trim();
        var slash = value.IndexOf('\\');
        if (slash > 0)
        {
            var netbios = value[..slash];
            return _options.Directories.SingleOrDefault(directory =>
                       directory.NetbiosNames.Contains(netbios, StringComparer.OrdinalIgnoreCase))
                   ?? throw new KeyNotFoundException("LDAP directory is not configured for this domain.");
        }

        var at = value.LastIndexOf('@');
        if (at > 0 && at < value.Length - 1)
        {
            var suffix = value[(at + 1)..];
            return _options.Directories.SingleOrDefault(directory =>
                       directory.UpnSuffixes.Contains(suffix, StringComparer.OrdinalIgnoreCase))
                   ?? throw new KeyNotFoundException("LDAP directory is not configured for this UPN suffix.");
        }

        return GetDirectory(_options.DefaultDirectoryKey);
    }

    public LdapDirectoryOptions GetDirectory(string directoryKey) =>
        _options.Directories.SingleOrDefault(directory =>
            string.Equals(directory.Key, directoryKey, StringComparison.OrdinalIgnoreCase))
        ?? throw new KeyNotFoundException("LDAP directory is not configured.");

    public Task<LdapDirectoryIdentity?> FindUserAsync(
        string directoryKey,
        string username,
        CancellationToken cancellationToken) =>
        RunBoundedAsync(() => FindUser(GetDirectory(directoryKey), username), cancellationToken);

    public Task<LdapCredentialValidationResult> ValidateCredentialsAsync(
        string directoryKey,
        string userPrincipalName,
        string password,
        CancellationToken cancellationToken) =>
        RunBoundedAsync(() => ValidateCredentials(GetDirectory(directoryKey), userPrincipalName, password), cancellationToken);

    public Task<bool> IsUserEnabledAsync(
        string directoryKey,
        Guid objectGuid,
        CancellationToken cancellationToken) =>
        RunBoundedAsync(() => FindByObjectGuid(GetDirectory(directoryKey), objectGuid)?.IsEnabled == true, cancellationToken);

    private async Task<T> RunBoundedAsync<T>(Func<T> operation, CancellationToken cancellationToken)
    {
        await _operations.WaitAsync(cancellationToken);
        try
        {
            // System.DirectoryServices.Protocols exposes synchronous bind/search APIs.
            // Once started, keep the concurrency lease until the bounded LDAP timeout
            // completes even if the HTTP request is cancelled.
            return await Task.Run(operation, CancellationToken.None);
        }
        finally
        {
            _operations.Release();
        }
    }

    private static LdapDirectoryIdentity? FindUser(LdapDirectoryOptions directory, string username)
    {
        var value = username.Trim();
        var slash = value.IndexOf('\\');
        if (slash >= 0)
        {
            value = value[(slash + 1)..];
        }

        var attribute = value.Contains('@') ? "userPrincipalName" : "sAMAccountName";
        var filter = $"(&(objectCategory=person)(objectClass=user)({attribute}={EscapeFilter(value)}))";
        return SearchSingle(directory, filter);
    }

    private static LdapDirectoryIdentity? FindByObjectGuid(LdapDirectoryOptions directory, Guid objectGuid)
    {
        var filter = $"(&(objectCategory=person)(objectClass=user)(objectGUID={EscapeBytes(objectGuid.ToByteArray())}))";
        return SearchSingle(directory, filter);
    }

    private static LdapDirectoryIdentity? SearchSingle(LdapDirectoryOptions directory, string filter)
    {
        Exception? lastTransportError = null;
        foreach (var host in directory.Hosts)
        {
            try
            {
                using var connection = CreateConnection(directory, host, directory.BindUsername, directory.BindPassword);
                connection.Bind();
                var request = new SearchRequest(
                    directory.BaseDn,
                    filter,
                    SearchScope.Subtree,
                    "objectGUID",
                    "userPrincipalName",
                    "sAMAccountName",
                    "userAccountControl")
                {
                    SizeLimit = 2,
                    TimeLimit = TimeSpan.FromSeconds(directory.TimeoutSeconds)
                };
                var response = (SearchResponse)connection.SendRequest(request);
                if (response.Entries.Count == 0)
                {
                    return null;
                }

                if (response.Entries.Count != 1)
                {
                    throw new LdapDirectoryUnavailableException("LDAP lookup returned more than one exact match.");
                }

                var entry = response.Entries[0];
                var guidBytes = (byte[])entry.Attributes["objectGUID"][0]!;
                var upn = entry.Attributes["userPrincipalName"]?[0]?.ToString();
                var sam = entry.Attributes["sAMAccountName"]?[0]?.ToString();
                if (string.IsNullOrWhiteSpace(upn) || string.IsNullOrWhiteSpace(sam))
                {
                    throw new LdapDirectoryUnavailableException("LDAP user is missing a required login attribute.");
                }

                var userAccountControl = entry.Attributes["userAccountControl"]?[0]?.ToString();
                _ = int.TryParse(userAccountControl, out var flags);
                return new LdapDirectoryIdentity(directory.Key, new Guid(guidBytes), upn, sam, (flags & 2) == 0);
            }
            catch (LdapDirectoryUnavailableException)
            {
                throw;
            }
            catch (Exception exception) when (exception is LdapException or DirectoryOperationException)
            {
                lastTransportError = exception;
            }
        }

        throw new LdapDirectoryUnavailableException("No LDAP directory server was available.", lastTransportError);
    }

    private static LdapCredentialValidationResult ValidateCredentials(
        LdapDirectoryOptions directory,
        string userPrincipalName,
        string password)
    {
        Exception? lastTransportError = null;
        foreach (var host in directory.Hosts)
        {
            try
            {
                using var connection = CreateConnection(directory, host, userPrincipalName, password);
                connection.Bind();
                return LdapCredentialValidationResult.Success;
            }
            catch (LdapException exception) when (exception.ErrorCode == LdapInvalidCredentialsErrorCode)
            {
                return LdapCredentialValidationResult.InvalidCredentials;
            }
            catch (Exception exception) when (exception is LdapException or DirectoryOperationException)
            {
                lastTransportError = exception;
            }
        }

        throw new LdapDirectoryUnavailableException("No LDAP directory server was available.", lastTransportError);
    }

    private static LdapConnection CreateConnection(
        LdapDirectoryOptions directory,
        string host,
        string username,
        string password)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(host, directory.Port, false, false))
        {
            AuthType = AuthType.Basic,
            Credential = new NetworkCredential(username, password),
            Timeout = TimeSpan.FromSeconds(directory.TimeoutSeconds)
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        return connection;
    }

    private static string EscapeFilter(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            builder.Append(character switch
            {
                '\\' => "\\5c",
                '*' => "\\2a",
                '(' => "\\28",
                ')' => "\\29",
                '\0' => "\\00",
                _ => character.ToString()
            });
        }
        return builder.ToString();
    }

    private static string EscapeBytes(byte[] value) =>
        string.Concat(value.Select(item => $"\\{item:x2}"));

    public void Dispose() => _operations.Dispose();
}
