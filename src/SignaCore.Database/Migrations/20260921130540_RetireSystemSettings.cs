using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations
{
    /// <inheritdoc />
    /// <remarks>
    /// The protected retirement of the legacy <c>system_settings</c> table. The guard is a fixed
    /// <c>DO</c> block that runs inside the migration transaction before the drop: existence only
    /// — no setting value is ever read — and a refusal raises a fixed exception, so the drop never
    /// happens. See <c>docs/database/system-settings-retirement.md</c>.
    /// </remarks>
    public partial class RetireSystemSettings : Migration
    {
        /// <summary>
        /// The fixed exception message raised when the guard refuses, so an operator running the
        /// migration outside startup can identify the refusal.
        /// </summary>
        public const string GuardRefusalMessage =
            "refusing to drop system_settings: the table still holds rows that were never " +
            "migrated into the shared service_settings aggregate of service signacore; " +
            "upgrade through a bridge build first";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql($"""
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM system_settings)
                       AND NOT EXISTS (
                           SELECT 1 FROM service_settings
                           WHERE service_id = 'signacore')
                    THEN
                        RAISE EXCEPTION '{GuardRefusalMessage}';
                    END IF;
                END
                $$;
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
