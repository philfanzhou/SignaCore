using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class EnableAppScopedSmsLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM otps;");
            migrationBuilder.Sql("UPDATE refresh_tokens SET is_revoked = 1 WHERE is_revoked = 0;");
            migrationBuilder.Sql("""
                UPDATE user_logins
                SET provider_user_id = CASE
                    WHEN provider_user_id REGEXP '^1[3-9][0-9]{9}$' THEN CONCAT('+86', provider_user_id)
                    WHEN provider_user_id REGEXP '^86[1][3-9][0-9]{9}$' THEN CONCAT('+', provider_user_id)
                    WHEN provider_user_id REGEXP '^0086[1][3-9][0-9]{9}$' THEN CONCAT('+', SUBSTRING(provider_user_id, 3))
                    ELSE provider_user_id
                END
                WHERE provider_name_normalized = 'SMS';
                """);
            migrationBuilder.DropIndex(
                name: "IX_otps_phone",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "code",
                table: "otps");

            migrationBuilder.AddColumn<Guid>(
                name: "sms_user_login_id",
                table: "refresh_tokens",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.AddColumn<Guid>(
                name: "app_registration_id",
                table: "otps",
                type: "char(36)",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                collation: "ascii_general_ci");

            migrationBuilder.AddColumn<string>(
                name: "code_mac",
                table: "otps",
                type: "varchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "",
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<int>(
                name: "day_send_count",
                table: "otps",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "day_window_started_at",
                table: "otps",
                type: "datetime(6)",
                precision: 6,
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<int>(
                name: "hour_send_count",
                table: "otps",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "hour_window_started_at",
                table: "otps",
                type: "datetime(6)",
                precision: 6,
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "profile_key",
                table: "otps",
                type: "varchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "",
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "provider",
                table: "otps",
                type: "varchar(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "",
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "provider_message_id",
                table: "otps",
                type: "varchar(128)",
                maxLength: 128,
                nullable: true,
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<DateTime>(
                name: "sent_at",
                table: "otps",
                type: "datetime(6)",
                precision: 6,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "status",
                table: "otps",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "sms_login_mode",
                table: "app_registrations",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "sms_profile_key",
                table: "app_registrations",
                type: "varchar(64)",
                maxLength: 64,
                nullable: true,
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "app_sms_accesses",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    app_registration_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    user_login_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    approval_source = table.Column<int>(type: "int", nullable: false),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    approved_by = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_sms_accesses", x => x.id);
                    table.ForeignKey(
                        name: "FK_app_sms_accesses_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_app_sms_accesses_user_logins_user_login_id",
                        column: x => x.user_login_id,
                        principalTable: "user_logins",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_sms_user_login_id",
                table: "refresh_tokens",
                column: "sms_user_login_id");

            migrationBuilder.CreateIndex(
                name: "IX_otps_app_registration_id_phone",
                table: "otps",
                columns: new[] { "app_registration_id", "phone" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_sms_accesses_app_registration_id_user_login_id",
                table: "app_sms_accesses",
                columns: new[] { "app_registration_id", "user_login_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_sms_accesses_user_login_id",
                table: "app_sms_accesses",
                column: "user_login_id");

            migrationBuilder.AddForeignKey(
                name: "FK_otps_app_registrations_app_registration_id",
                table: "otps",
                column: "app_registration_id",
                principalTable: "app_registrations",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM otps;");
            migrationBuilder.DropForeignKey(
                name: "FK_otps_app_registrations_app_registration_id",
                table: "otps");

            migrationBuilder.DropTable(
                name: "app_sms_accesses");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_sms_user_login_id",
                table: "refresh_tokens");

            migrationBuilder.DropIndex(
                name: "IX_otps_app_registration_id_phone",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "sms_user_login_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "app_registration_id",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "code_mac",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "day_send_count",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "day_window_started_at",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "hour_send_count",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "hour_window_started_at",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "profile_key",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "provider",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "provider_message_id",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "sent_at",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "status",
                table: "otps");

            migrationBuilder.DropColumn(
                name: "sms_login_mode",
                table: "app_registrations");

            migrationBuilder.DropColumn(
                name: "sms_profile_key",
                table: "app_registrations");

            migrationBuilder.AddColumn<string>(
                name: "code",
                table: "otps",
                type: "varchar(10)",
                maxLength: 10,
                nullable: false,
                defaultValue: "",
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_otps_phone",
                table: "otps",
                column: "phone",
                unique: true);
        }
    }
}
