using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.ReferenceBff.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementRoleBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "management_role_bindings",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    role = table.Column<string>(type: "text", nullable: false),
                    issuer = table.Column<string>(type: "text", nullable: false),
                    subject = table.Column<string>(type: "text", nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_management_role_bindings", x => x.id);
                    table.CheckConstraint("CK_management_role_bindings_role_fixed", "role = 'system-administrator'");
                });

            migrationBuilder.CreateIndex(
                name: "IX_management_role_bindings_role",
                table: "management_role_bindings",
                column: "role",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "management_role_bindings");
        }
    }
}
