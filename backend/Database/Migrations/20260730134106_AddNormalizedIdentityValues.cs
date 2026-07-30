using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddNormalizedIdentityValues : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "provider_name_normalized",
                table: "user_logins",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "username_normalized",
                table: "password_credentials",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "username_normalized",
                table: "login_attempts",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "app_id_normalized",
                table: "app_registrations",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "nickname_normalized",
                table: "accounts",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "remark_normalized",
                table: "accounts",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "provider_name_normalized",
                table: "user_logins");

            migrationBuilder.DropColumn(
                name: "username_normalized",
                table: "password_credentials");

            migrationBuilder.DropColumn(
                name: "username_normalized",
                table: "login_attempts");

            migrationBuilder.DropColumn(
                name: "app_id_normalized",
                table: "app_registrations");

            migrationBuilder.DropColumn(
                name: "nickname_normalized",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "remark_normalized",
                table: "accounts");
        }
    }
}
