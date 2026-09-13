using Microsoft.Data.Sqlite;
using ServiceMantle.Bootstrap;

namespace SignaCore.Host.Migration;

/// <summary>
/// Declares SignaCore's SQLite host deployment strategy: a single process owning one local file.
/// Only the canonical target identity of the existing connection string is resolved here; creating
/// databases, new-file safety protocols, and any migration lease are not this type's job, so it
/// never masquerades as cross-process coordination.
/// </summary>
internal sealed class SqliteDeploymentCapabilityProvider : IDatabaseDeploymentCapabilityProvider
{
    public DatabaseDeploymentCapability Capability { get; } = new(
        WellKnownDatabaseProviderIds.Sqlite,
        DatabaseDeploymentSupport.SingleInstanceOnly);

    /// <inheritdoc />
    public ValueTask<string> GetCanonicalTargetIdentityAsync(
        BootstrapDatabaseConfiguration target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        cancellationToken.ThrowIfCancellationRequested();

        var builder = new SqliteConnectionStringBuilder(target.ConnectionString);
        var dataSource = builder.DataSource;

        if (string.IsNullOrWhiteSpace(dataSource))
        {
            throw new InvalidOperationException(
                "SQLite connection string must specify Data Source.");
        }

        // Ordinary paths are normalized to full paths so that relative and absolute spellings that
        // resolve to the same file share one process-local turn, while different files stay
        // distinct. Connection-string spelling, parameter order, and options such as timeouts do
        // not affect the identity. "file:" URI targets are used verbatim; filesystem links, mount
        // aliases, and external replacement are outside the mutual-exclusion guarantee.
        string identity;
        if (dataSource.StartsWith("file:", StringComparison.Ordinal))
        {
            identity = dataSource.Trim();
        }
        else
        {
            identity = Path.GetFullPath(dataSource);
        }

        return ValueTask.FromResult(identity);
    }
}
