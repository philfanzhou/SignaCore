using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.ReferenceBff.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddSharedDataProtectionKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "service_data_protection_keys",
                columns: table => new
                {
                    service_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    key_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    encrypted_xml = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_data_protection_keys", x => new { x.service_id, x.key_id });
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "service_data_protection_keys");
        }
    }
}
