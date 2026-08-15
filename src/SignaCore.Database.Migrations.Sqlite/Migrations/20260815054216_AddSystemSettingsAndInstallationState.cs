using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddSystemSettingsAndInstallationState : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "installation_state",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false),
                    status = table.Column<int>(type: "INTEGER", nullable: false),
                    installation_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    setup_code_hash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    setup_code_expires_at = table.Column<long>(type: "INTEGER", nullable: true),
                    completed_at = table.Column<long>(type: "INTEGER", nullable: true),
                    configuration_version = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_installation_state", x => x.id);
                    table.CheckConstraint("CK_installation_state_singleton", "id = 1");
                });

            migrationBuilder.CreateTable(
                name: "system_settings",
                columns: table => new
                {
                    key = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    value = table.Column<string>(type: "TEXT", nullable: false),
                    value_type = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    is_secret = table.Column<bool>(type: "INTEGER", nullable: false),
                    version = table.Column<int>(type: "INTEGER", nullable: false),
                    updated_at = table.Column<long>(type: "INTEGER", nullable: false),
                    updated_by = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_system_settings", x => x.key);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "installation_state");

            migrationBuilder.DropTable(
                name: "system_settings");
        }
    }
}
