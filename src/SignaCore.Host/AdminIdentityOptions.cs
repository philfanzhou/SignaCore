namespace SignaCore.Host;

/// <summary>
/// Which account is the deployment's administrator.
/// <para>
/// This used to arrive as <c>ADMIN_BOOTSTRAP_USERNAME</c> / <c>ADMIN_BOOTSTRAP_PASSWORD</c> on the
/// launcher, which meant every deployment had to hand a plaintext administrator password to the
/// process environment. First-run setup now creates the account behind the one-time setup code and
/// records only the username as a global setting; the password exists solely as its hash in
/// <c>password_credentials</c>.
/// </para>
/// </summary>
public sealed class AdminIdentityOptions
{
    public string Username { get; init; } = string.Empty;

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Username);
}
