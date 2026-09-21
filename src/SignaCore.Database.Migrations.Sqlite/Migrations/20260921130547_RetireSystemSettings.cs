using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    /// <remarks>
    /// The protected retirement of the legacy <c>system_settings</c> table. SQLite has no
    /// procedural SQL, so the guard is a temp table with a CHECK constraint: the verdict is
    /// computed by a plain query (existence only — no setting value is ever read) and inserting
    /// <c>refuse</c> violates the constraint, aborting the statement and the surrounding migration
    /// transaction before the drop. See <c>docs/database/system-settings-retirement.md</c>.
    /// </remarks>
    public partial class RetireSystemSettings : Migration
    {
        /// <summary>
        /// The fixed CHECK-constraint name that surfaces when the guard refuses, so an operator
        /// running the migration outside startup can identify the refusal.
        /// </summary>
        public const string GuardConstraintName = "CK_system_settings_retirement_guard";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql($"""
                DROP TABLE IF EXISTS temp.system_settings_retirement_guard;
                CREATE TEMP TABLE system_settings_retirement_guard (
                    verdict TEXT NOT NULL,
                    CONSTRAINT {GuardConstraintName} CHECK (verdict = 'proceed')
                );
                INSERT INTO system_settings_retirement_guard (verdict)
                SELECT CASE
                    WHEN EXISTS (SELECT 1 FROM system_settings)
                         AND NOT EXISTS (
                             SELECT 1 FROM service_settings
                             WHERE service_id = 'signacore')
                    THEN 'refuse' ELSE 'proceed'
                END;
                DROP TABLE system_settings_retirement_guard;
                """);

            migrationBuilder.DropTable(
                name: "system_settings");
        }

        /// <inheritdoc />
        /// <remarks>
        /// The drop is irreversible by design: recreating an empty table would masquerade as a
        /// restore while the retired rows stay gone. A downgrade restores a backup instead.
        /// </remarks>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException(
                "Downgrading does not restore the retired system_settings table; the drop is " +
                "irreversible. Restore the database from a backup taken before the upgrade " +
                "instead. See docs/database/system-settings-retirement.md.");
        }
    }
}
