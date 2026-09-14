namespace SignaCore.Host.Management;

/// <summary>
/// The scoped credential accessor that carries one management login attempt's credentials from the
/// login adapter to the identity provider.
/// </summary>
/// <remarks>
/// ServiceMantle deliberately keeps request objects and credentials out of
/// <c>IManagementIdentityProvider</c>. This accessor is SignaCore's own trusted channel: the login
/// adapter is the only writer, the provider is the only reader, and both are scoped to the same
/// login request, so the credentials never travel through any public contract.
/// </remarks>
internal sealed class ManagementCredentialAccessor
{
    /// <summary>Whether credentials were placed by the login adapter.</summary>
    public bool HasCredentials { get; private set; }

    /// <summary>The submitted username, trimmed by the adapter.</summary>
    public string Username { get; private set; } = string.Empty;

    /// <summary>The submitted password, kept verbatim.</summary>
    public string Password { get; private set; } = string.Empty;

    /// <summary>Places the parsed credentials. Callers must not re-enter with blank values.</summary>
    public void Set(string username, string password)
    {
        Username = username;
        Password = password;
        HasCredentials = true;
    }
}
