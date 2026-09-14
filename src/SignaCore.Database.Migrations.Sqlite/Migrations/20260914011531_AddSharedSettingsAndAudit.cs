using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddSharedSettingsAndAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "service_audit_logs",
                columns: table => new
                {
                    id = table.Column<string>(type: "TEXT", maxLength: 36, nullable: false),
                    operator_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    operator_display_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    operator_source = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    action = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    target_type = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    target_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    outcome = table.Column<int>(type: "INTEGER", nullable: false),
                    occurred_at_utc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    client_ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    correlation_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    security_description = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    metadata_json = table.Column<string>(type: "TEXT", maxLength: 262144, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_audit_logs", x => x.id);
                    table.CheckConstraint("ck_service_audit_logs_action_length", "action IS NULL OR octet_length(action) <= 800");
                    table.CheckConstraint("ck_service_audit_logs_client_ip_length", "client_ip IS NULL OR octet_length(client_ip) <= 256");
                    table.CheckConstraint("ck_service_audit_logs_correlation_id_length", "correlation_id IS NULL OR octet_length(correlation_id) <= 512");
                    table.CheckConstraint("ck_service_audit_logs_id_length", "id IS NULL OR octet_length(id) <= 144");
                    table.CheckConstraint("ck_service_audit_logs_id_not_empty", "id <> '00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("ck_service_audit_logs_metadata_json_length", "metadata_json IS NULL OR octet_length(metadata_json) <= 262144");
                    table.CheckConstraint("ck_service_audit_logs_operator_display_name_length", "operator_display_name IS NULL OR octet_length(operator_display_name) <= 1024");
                    table.CheckConstraint("ck_service_audit_logs_operator_id_length", "operator_id IS NULL OR octet_length(operator_id) <= 1024");
                    table.CheckConstraint("ck_service_audit_logs_operator_source_length", "operator_source IS NULL OR octet_length(operator_source) <= 400");
                    table.CheckConstraint("ck_service_audit_logs_security_description_length", "security_description IS NULL OR octet_length(security_description) <= 16000");
                    table.CheckConstraint("ck_service_audit_logs_target_id_length", "target_id IS NULL OR octet_length(target_id) <= 1024");
                    table.CheckConstraint("ck_service_audit_logs_target_type_length", "target_type IS NULL OR octet_length(target_type) <= 800");
                });

            migrationBuilder.CreateTable(
                name: "service_settings",
                columns: table => new
                {
                    service_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    values_json = table.Column<string>(type: "TEXT", nullable: false),
                    version = table.Column<long>(type: "INTEGER", nullable: false),
                    updated_at_utc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_by = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    restart_required = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_settings", x => x.service_id);
                    table.CheckConstraint("ck_service_settings_version", "version > 0");
                });

            migrationBuilder.CreateIndex(
                name: "ix_service_audit_logs_action_occurred_at_utc_id",
                table: "service_audit_logs",
                columns: new[] { "action", "occurred_at_utc", "id" });

            migrationBuilder.CreateIndex(
                name: "ix_service_audit_logs_occurred_at_utc_id",
                table: "service_audit_logs",
                columns: new[] { "occurred_at_utc", "id" });

            migrationBuilder.CreateIndex(
                name: "ix_service_audit_logs_operator_id_occurred_at_utc_id",
                table: "service_audit_logs",
                columns: new[] { "operator_id", "occurred_at_utc", "id" });

            migrationBuilder.CreateIndex(
                name: "ix_service_audit_logs_target_id_occurred_at_utc_id",
                table: "service_audit_logs",
                columns: new[] { "target_id", "occurred_at_utc", "id" });

            migrationBuilder.CreateIndex(
                name: "ix_service_audit_logs_target_occurred_at_utc_id",
                table: "service_audit_logs",
                columns: new[] { "target_type", "target_id", "occurred_at_utc", "id" });

            migrationBuilder.CreateIndex(
                name: "ix_service_audit_logs_target_type_occurred_at_utc_id",
                table: "service_audit_logs",
                columns: new[] { "target_type", "occurred_at_utc", "id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "service_audit_logs");

            migrationBuilder.DropTable(
                name: "service_settings");
        }
    }
}
