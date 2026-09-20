using Microsoft.EntityFrameworkCore;

namespace SignaCore.ReferenceBff.Database;

/// <summary>Outcome of staging the initial administrator binding.</summary>
public enum ManagementRoleBindingStagingStatus
{
    /// <summary>The binding was added to the change tracker only; the caller still owns the save.</summary>
    Staged,

    /// <summary>The slot is already bound — active or not; nothing was staged.</summary>
    SlotAlreadyBound
}

/// <summary>Outcome of an exact-match read of the administrator binding.</summary>
public enum ManagementRoleBindingMatchStatus
{
    /// <summary>The presented identity matches the active binding byte-for-byte.</summary>
    MatchedActiveAdministrator,

    /// <summary>No binding row exists yet.</summary>
    NoBindingPresent,

    /// <summary>A binding row exists but is deactivated; it grants nothing.</summary>
    BindingInactive,

    /// <summary>
    /// The presented identity does not match the stored binding — including empty or unknown values.
    /// </summary>
    IdentityMismatch
}

/// <summary>
/// Staging and exact-match read boundary of the reference BFF's single initial-administrator
/// binding. The store never saves, commits, retries, or overwrites: staging only adds an entity to
/// the change tracker, and the caller owns the transaction and its single save. Staging is
/// therefore not evidence that the administrator was bound.
/// <para>
/// Identity values are the raw OIDC-asserted issuer and subject, byte-for-byte: they are stored
/// untrimmed and un-folded, and matching happens in the CLR with
/// <see cref="string.Equals(string?, string?, StringComparison)"/> after reading the fixed role
/// row, so database collation can neither fold nor widen a value and no index is needed over the
/// identity columns.
/// </para>
/// </summary>
public sealed class ManagementRoleBindingStore(ReferenceBffDbContext context)
{
    /// <summary>
    /// Stages the initial administrator binding for the verified identity. Fails — without staging
    /// anything — when the slot is already bound, whether by a committed row (active or not) or by
    /// a row this context has already staged. The unique index on the role remains the final
    /// arbiter for racing writers on separate connections.
    /// </summary>
    public async ValueTask<ManagementRoleBindingStagingStatus> StageInitialAdministratorAsync(
        string issuer,
        string subject,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfNotAVerifiedIdentity(issuer, "issuer");
        ThrowIfNotAVerifiedIdentity(subject, "subject");

        // A deactivated row still occupies the slot: the first administrator can never be
        // re-claimed through a missing active row.
        if (await context.ManagementRoleBindings.AsNoTracking().AnyAsync(
                binding => binding.Role == ManagementRoleBindingEntity.SystemAdministratorRole,
                cancellationToken)
            || context.ChangeTracker.Entries<ManagementRoleBindingEntity>().Any(
                entry => entry.State is EntityState.Added or EntityState.Modified
                    && entry.Entity.Role == ManagementRoleBindingEntity.SystemAdministratorRole))
        {
            return ManagementRoleBindingStagingStatus.SlotAlreadyBound;
        }

        context.ManagementRoleBindings.Add(new ManagementRoleBindingEntity
        {
            Id = Guid.NewGuid(),
            Role = ManagementRoleBindingEntity.SystemAdministratorRole,
            Issuer = issuer,
            Subject = subject,
            IsActive = true,
            CreatedAtUtc = DateTimeOffset.UtcNow
        });

        return ManagementRoleBindingStagingStatus.Staged;
    }

    /// <summary>
    /// Reads the fixed role row and answers whether the presented verified identity is exactly the
    /// active bound administrator. Unknown, empty, inactive, or any non-matching pair answers a
    /// no-permission outcome; this method never stages or saves anything.
    /// </summary>
    public async ValueTask<ManagementRoleBindingMatchStatus> MatchAdministratorAsync(
        string issuer,
        string subject,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (issuer.Length == 0 || subject.Length == 0)
        {
            return ManagementRoleBindingMatchStatus.IdentityMismatch;
        }

        var binding = await context.ManagementRoleBindings.AsNoTracking().SingleOrDefaultAsync(
            binding => binding.Role == ManagementRoleBindingEntity.SystemAdministratorRole,
            cancellationToken);
        if (binding is null)
        {
            return ManagementRoleBindingMatchStatus.NoBindingPresent;
        }

        if (!binding.IsActive)
        {
            return ManagementRoleBindingMatchStatus.BindingInactive;
        }

        // Ordinal comparison in the CLR only: no database collation participates in the decision.
        if (!string.Equals(binding.Issuer, issuer, StringComparison.Ordinal)
            || !string.Equals(binding.Subject, subject, StringComparison.Ordinal))
        {
            return ManagementRoleBindingMatchStatus.IdentityMismatch;
        }

        return ManagementRoleBindingMatchStatus.MatchedActiveAdministrator;
    }

    private static void ThrowIfNotAVerifiedIdentity(string value, string name)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException(
                $"The verified {name} of the initial administrator must be a non-empty value.",
                name);
        }
    }
}
