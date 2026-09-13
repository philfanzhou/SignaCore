namespace SignaCore.Host.Installation;

/// <summary>
/// Carries the initial administrator's credentials from the validated setup request into a
/// contributor instance.
/// <para>
/// The password exists only to produce its hash. Every string projection is overridden so the
/// plaintext can never reach a log line, an exception message, or a debugger display through
/// this type, and instances live only for the duration of a single transaction attempt.
/// </para>
/// </summary>
internal sealed class InitialAdministratorSetupInput
{
    public InitialAdministratorSetupInput(string username, string password)
    {
        Username = username;
        Password = password;
    }

    /// <summary>The already-trimmed administrator username.</summary>
    public string Username { get; }

    /// <summary>The administrator plaintext password; used only to derive its hash.</summary>
    public string Password { get; }

    public override string ToString() => nameof(InitialAdministratorSetupInput);
}
