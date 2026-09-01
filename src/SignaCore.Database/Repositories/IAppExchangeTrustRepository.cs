using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

/// <summary>
/// Directed trust edges consulted when a refresh token is presented by an application other than the
/// one it was issued to. See docs/adr/0003-cross-application-refresh-grant.md.
/// </summary>
public interface IAppExchangeTrustRepository
{
    /// <summary>
    /// True when <paramref name="appRegistrationId"/> accepts refresh tokens issued to
    /// <paramref name="sourceAppId"/> and that source application is still active. A deactivated
    /// source application is treated as having no edge.
    /// </summary>
    Task<bool> IsTrustedSourceAsync(
        Guid appRegistrationId,
        string sourceAppId,
        CancellationToken cancellationToken = default);

    /// <summary>Source applications trusted by <paramref name="appRegistrationId"/>, newest first.</summary>
    Task<IReadOnlyList<AppExchangeTrust>> ListSourcesAsync(
        Guid appRegistrationId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stages an edge if it is absent and returns it. Returns the existing edge unchanged when the
    /// pair is already trusted, so adding twice is not an error. The caller commits the unit of work.
    /// </summary>
    Task<AppExchangeTrust> AddAsync(
        AppRegistrationEntity app,
        AppRegistrationEntity sourceApp,
        Guid? approvedBy,
        CancellationToken cancellationToken = default);

    /// <summary>Stages removal of the edge. False when it did not exist. The caller commits the unit of work.</summary>
    Task<bool> RemoveAsync(
        Guid appRegistrationId,
        Guid sourceAppRegistrationId,
        CancellationToken cancellationToken = default);
}

/// <summary>One edge, joined with the source application so callers can show a name.</summary>
public sealed record AppExchangeTrust(
    Guid SourceAppRegistrationId,
    string SourceAppId,
    string SourceAppName,
    bool SourceIsActive,
    Guid? ApprovedBy,
    DateTimeOffset CreatedAt);
