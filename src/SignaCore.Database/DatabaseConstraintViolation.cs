using Microsoft.EntityFrameworkCore;

namespace SignaCore.Database;

/// <summary>
/// The single classifier of database foreign-key violations across the two supported providers.
/// The database's restrictive reference is the only authority for "still referenced" decisions
/// (<c>PS-23</c>): no pre-check, no per-table enumeration, no race window. Any other
/// <see cref="DbUpdateException"/> stays what it was — an unexpected failure for the generic
/// handler.
/// </summary>
public static class DatabaseConstraintViolation
{
    /// <summary>
    /// PostgreSQL reports SQLSTATE <c>23503</c>; SQLite reports <c>SQLITE_CONSTRAINT</c> (19) with
    /// the foreign-key extended code (<c>787</c>) — or, for its immediately executed
    /// <c>ON DELETE RESTRICT</c>, the trigger extended code (<c>1811</c>) with the foreign-key
    /// message. Both migration histories carry no user triggers, so the trigger code cannot be
    /// produced by anything else here.
    /// </summary>
    public static bool IsForeignKeyViolation(DbUpdateException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception.InnerException switch
        {
            Npgsql.PostgresException postgres =>
                postgres.SqlState == Npgsql.PostgresErrorCodes.ForeignKeyViolation,
            Microsoft.Data.Sqlite.SqliteException sqlite =>
                sqlite.SqliteErrorCode == 19
                && sqlite.SqliteExtendedErrorCode is 787 or 1811,
            _ => false
        };
    }
}
