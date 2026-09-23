using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class UnmapLegacyAuditLogs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Intentionally empty: the model drops the AuditLogEntity mapping, but the physical
            // audit_logs table and its history rows are retained as-is (ServiceMantle #132,
            // 2026-09-23 ruling). Fresh databases still create the table through the historical
            // AddLoginHistoryAndAuditLog migration; nothing writes to or reads from it anymore.
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // No schema operation was applied, so none is reverted. The AuditLogEntity mapping
            // returns with the model snapshot change; existing rows were never touched.
        }
    }
}
