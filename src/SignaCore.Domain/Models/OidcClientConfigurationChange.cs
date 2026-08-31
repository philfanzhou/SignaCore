using SignaCore.Database.Entity;

namespace SignaCore.Domain.Models;

/// <summary>
/// The result of accepting an interactive OIDC configuration: the validated values plus the URI
/// registrations the caller still has to stage with its own context.
/// <para>
/// The registration lists are explicit rather than left to navigation fixup, because whether a new
/// child of an already-tracked parent is treated as an insert or an update is a provider and
/// key-generation detail. Naming the inserts and deletes keeps the outcome the same everywhere.
/// A caller that is adding a brand-new application can ignore both lists: adding the application
/// itself already stages its whole graph.
/// </para>
/// </summary>
public sealed record OidcClientConfigurationChange(
    ValidatedOidcClientConfiguration Configuration,
    IReadOnlyList<AppRedirectUriEntity> AddedRegistrations,
    IReadOnlyList<AppRedirectUriEntity> RemovedRegistrations);
