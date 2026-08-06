using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.MySql.Migrations
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
                type: "varchar(100)",
                maxLength: 100,
                nullable: false,
                collation: "utf8mb4_bin",
                oldClrType: typeof(string),
                oldType: "varchar(100)",
                oldMaxLength: 100,
                oldNullable: true)
                .Annotation("MySql:CharSet", "utf8mb4")
                .OldAnnotation("MySql:CharSet", "utf8mb4")
                .OldAnnotation("Relational:Collation", "utf8mb4_bin");

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
                type: "varchar(100)",
                maxLength: 100,
                nullable: true,
                collation: "utf8mb4_bin",
                oldClrType: typeof(string),
                oldType: "varchar(100)",
                oldMaxLength: 100)
                .Annotation("MySql:CharSet", "utf8mb4")
                .OldAnnotation("MySql:CharSet", "utf8mb4")
                .OldAnnotation("Relational:Collation", "utf8mb4_bin");
        }
    }
}
