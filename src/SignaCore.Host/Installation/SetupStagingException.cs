namespace SignaCore.Host.Installation;

/// <summary>
/// The fixed, safe failure first-run setup reports when staging the installation slice could not be
/// completed: the initial administrator, the settings snapshot, the installation audit event, or
/// the single save that commits them together failed, and the transaction was rolled back.
/// <para>
/// The message is fixed and the exception never carries an inner exception, so no database
/// constraint name, cryptographic detail, or provider text can travel through logs or the generic
/// HTTP error handling. The installation remains pending and its setup code is preserved.
/// </para>
/// </summary>
internal sealed class SetupStagingException : Exception
{
    internal const string FixedMessage =
        "First-run setup failed while staging the installation. The installation remains pending.";

    internal SetupStagingException()
        : base(FixedMessage)
    {
    }

    public override string ToString() =>
        $"{nameof(SetupStagingException)}: {FixedMessage}";
}
