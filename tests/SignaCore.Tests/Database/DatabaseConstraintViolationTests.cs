using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Moq;
using SignaCore.Database;
using Xunit;

namespace SignaCore.Tests.Database;

/// <summary>
/// The provider shapes of <see cref="DatabaseConstraintViolation.IsForeignKeyViolation"/>: only a
/// real PostgreSQL foreign-key violation (SQLSTATE 23503) and SQLite's foreign-key constraint
/// shapes (19 with extended code 787, or 1811 for the immediately executed ON DELETE RESTRICT)
/// answer true; every other <see cref="DbUpdateException"/> — unique violations, connection
/// failures, missing inner exceptions, unrelated inner types — stays false so the generic handler
/// keeps owning it.
/// </summary>
public sealed class DatabaseConstraintViolationTests
{
    [Fact]
    public void PostgreSqlForeignKeyViolation_IsRecognized()
    {
        var exception = Wrap(new Npgsql.PostgresException(
            "update or delete on table violates foreign key constraint",
            "ERROR",
            "ERROR",
            Npgsql.PostgresErrorCodes.ForeignKeyViolation));

        Assert.True(DatabaseConstraintViolation.IsForeignKeyViolation(exception));
    }

    [Fact]
    public void PostgreSqlUniqueViolation_IsNotAForeignKeyViolation()
    {
        var exception = Wrap(new Npgsql.PostgresException(
            "duplicate key value violates unique constraint",
            "ERROR",
            "ERROR",
            Npgsql.PostgresErrorCodes.UniqueViolation));

        Assert.False(DatabaseConstraintViolation.IsForeignKeyViolation(exception));
    }

    [Theory]
    [InlineData(787)]
    [InlineData(1811)]
    public void SqliteForeignKeyConstraintShapes_AreRecognized(int extendedErrorCode)
    {
        var exception = Wrap(new SqliteException(
            "FOREIGN KEY constraint failed",
            19,
            extendedErrorCode));

        Assert.True(DatabaseConstraintViolation.IsForeignKeyViolation(exception));
    }

    [Fact]
    public void SqliteUniqueViolation_IsNotAForeignKeyViolation()
    {
        var exception = Wrap(new SqliteException(
            "UNIQUE constraint failed: accounts.username",
            19,
            2067));

        Assert.False(DatabaseConstraintViolation.IsForeignKeyViolation(exception));
    }

    [Fact]
    public void WithoutAnInnerException_IsNotAForeignKeyViolation()
    {
        Assert.False(DatabaseConstraintViolation.IsForeignKeyViolation(
            new DbUpdateException("An error occurred while saving the entity changes.")));
    }

    [Fact]
    public void WithAnUnrelatedInnerException_IsNotAForeignKeyViolation()
    {
        var exception = Wrap(new IOException("The connection was lost."));

        Assert.False(DatabaseConstraintViolation.IsForeignKeyViolation(exception));
    }

    private static DbUpdateException Wrap(Exception innerException) =>
        new("An error occurred while saving the entity changes.", innerException);
}
