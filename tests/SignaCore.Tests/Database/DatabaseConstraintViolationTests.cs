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
/// keeps owning it. <see cref="DatabaseConstraintViolation.IsUniqueViolation"/> is the mirror image:
/// only SQLSTATE 23505 and SQLite's unique (2067) or primary-key (1555) shapes answer true.
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

    // ---- IsUniqueViolation ----

    [Fact]
    public void PostgreSqlUniqueViolation_IsRecognized()
    {
        var exception = Wrap(new Npgsql.PostgresException(
            "duplicate key value violates unique constraint",
            "ERROR",
            "ERROR",
            Npgsql.PostgresErrorCodes.UniqueViolation));

        Assert.True(DatabaseConstraintViolation.IsUniqueViolation(exception));
    }

    [Fact]
    public void PostgreSqlForeignKeyViolation_IsNotAUniqueViolation()
    {
        var exception = Wrap(new Npgsql.PostgresException(
            "insert or update on table violates foreign key constraint",
            "ERROR",
            "ERROR",
            Npgsql.PostgresErrorCodes.ForeignKeyViolation));

        Assert.False(DatabaseConstraintViolation.IsUniqueViolation(exception));
    }

    [Theory]
    [InlineData(2067)]
    [InlineData(1555)]
    public void SqliteUniqueAndPrimaryKeyShapes_AreUniqueViolations(int extendedErrorCode)
    {
        var exception = Wrap(new SqliteException("UNIQUE constraint failed", 19, extendedErrorCode));

        Assert.True(DatabaseConstraintViolation.IsUniqueViolation(exception));
    }

    [Theory]
    [InlineData(19, 787)]
    [InlineData(19, 275)]
    [InlineData(5, 5)]
    public void OtherSqliteShapes_AreNotUniqueViolations(int errorCode, int extendedErrorCode)
    {
        var exception = Wrap(new SqliteException("constraint or busy failure", errorCode, extendedErrorCode));

        Assert.False(DatabaseConstraintViolation.IsUniqueViolation(exception));
    }

    [Fact]
    public void WithoutAnInnerException_IsNotAUniqueViolation()
    {
        Assert.False(DatabaseConstraintViolation.IsUniqueViolation(
            new DbUpdateException("An error occurred while saving the entity changes.")));
        Assert.False(DatabaseConstraintViolation.IsUniqueViolation(Wrap(new IOException("The connection was lost."))));
    }

    private static DbUpdateException Wrap(Exception innerException) =>
        new("An error occurred while saving the entity changes.", innerException);
}
