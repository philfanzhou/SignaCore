using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class DropInstallationState : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "installation_state");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "installation_state",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false),
                    completed_at = table.Column<long>(type: "INTEGER", nullable: true),
                    configuration_version = table.Column<int>(type: "INTEGER", nullable: false),
                    installation_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    setup_code_expires_at = table.Column<long>(type: "INTEGER", nullable: true),
                    setup_code_hash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    status = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_installation_state", x => x.id);
                    table.CheckConstraint("CK_installation_state_singleton", "id = 1");
                });
        }
    }
}
