using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class EnableAppScopedWechatLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "wechat_user_login_id",
                table: "refresh_tokens",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.AddColumn<int>(
                name: "wechat_login_mode",
                table: "app_registrations",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "app_wechat_accesses",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    app_registration_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    user_login_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    approval_source = table.Column<int>(type: "int", nullable: false),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_wechat_accesses", x => x.id);
                    table.ForeignKey(
                        name: "FK_app_wechat_accesses_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_app_wechat_accesses_user_logins_user_login_id",
                        column: x => x.user_login_id,
                        principalTable: "user_logins",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_wechat_user_login_id",
                table: "refresh_tokens",
                column: "wechat_user_login_id");

            migrationBuilder.CreateIndex(
                name: "IX_app_wechat_accesses_app_registration_id_user_login_id",
                table: "app_wechat_accesses",
                columns: new[] { "app_registration_id", "user_login_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_wechat_accesses_user_login_id",
                table: "app_wechat_accesses",
                column: "user_login_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "app_wechat_accesses");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_wechat_user_login_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "wechat_user_login_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "wechat_login_mode",
                table: "app_registrations");
        }
    }
}
