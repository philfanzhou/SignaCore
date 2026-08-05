using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class EnforceRefreshTokenAppBinding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM refresh_tokens WHERE app_id IS NULL OR app_id = '';");

            migrationBuilder.AlterColumn<string>(
                name: "app_id",
                table: "refresh_tokens",
                type: "TEXT",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 100,
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_refresh_tokens_app_id_not_empty",
                table: "refresh_tokens",
                sql: "app_id <> ''");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_refresh_tokens_app_id_not_empty",
                table: "refresh_tokens");

            migrationBuilder.AlterColumn<string>(
                name: "app_id",
                table: "refresh_tokens",
                type: "TEXT",
                maxLength: 100,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 100);
        }
    }
}
