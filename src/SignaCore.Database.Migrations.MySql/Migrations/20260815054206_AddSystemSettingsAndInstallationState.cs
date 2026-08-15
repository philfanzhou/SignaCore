using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.MySql.Migrations
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
                    id = table.Column<int>(type: "int", nullable: false),
                    status = table.Column<int>(type: "int", nullable: false),
                    installation_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    setup_code_hash = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    setup_code_expires_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: true),
                    completed_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: true),
                    configuration_version = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_installation_state", x => x.id);
                    table.CheckConstraint("CK_installation_state_singleton", "id = 1");
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "system_settings",
                columns: table => new
                {
                    key = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    value = table.Column<string>(type: "longtext", nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    value_type = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    is_secret = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    version = table.Column<int>(type: "int", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    updated_by = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_system_settings", x => x.key);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");
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
