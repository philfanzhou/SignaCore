using Xunit;

namespace SignaCore.Tests.Domain.Keys;

/// <summary>
/// Groups every test class that mutates process-level master key state into one collection so they
/// cannot trample each other in parallel.
/// <para>
/// Two pieces of shared state are involved, both global to the process or the file system:
/// <list type="bullet">
/// <item>the <c>RSA_MASTER_KEY</c> environment variable</item>
/// <item>the file <c>{BaseDirectory}/data/master-key/master-key.json</c></item>
/// </list>
/// xUnit runs different test classes in parallel by default; classes in the same collection run
/// serially. Without this constraint, roughly one in five full runs failed intermittently.
/// </para>
/// </summary>
[CollectionDefinition(Name)]
public sealed class MasterKeyStateCollection
{
    public const string Name = "MasterKeyState";
}
