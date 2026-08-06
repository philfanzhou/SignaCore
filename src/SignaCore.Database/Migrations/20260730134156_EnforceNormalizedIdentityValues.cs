using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations
{
    /// <inheritdoc />
    public partial class EnforceNormalizedIdentityValues : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_user_logins_provider_name_provider_user_id",
                table: "user_logins");

            migrationBuilder.DropIndex(
                name: "IX_password_credentials_username",
                table: "password_credentials");

            migrationBuilder.DropIndex(
                name: "IX_login_attempts_username",
                table: "login_attempts");

            migrationBuilder.DropIndex(
                name: "IX_app_registrations_app_id",
                table: "app_registrations");

            migrationBuilder.AlterColumn<string>(
                name: "provider_name_normalized",
                table: "user_logins",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "username_normalized",
                table: "password_credentials",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "username_normalized",
                table: "login_attempts",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "app_id_normalized",
                table: "app_registrations",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100,
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_user_logins_provider_name_normalized_provider_user_id",
                table: "user_logins",
                columns: new[] { "provider_name_normalized", "provider_user_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_password_credentials_username_normalized",
                table: "password_credentials",
                column: "username_normalized",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_login_attempts_username_normalized",
                table: "login_attempts",
                column: "username_normalized",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_registrations_app_id_normalized",
                table: "app_registrations",
                column: "app_id_normalized",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_user_logins_provider_name_normalized_provider_user_id",
                table: "user_logins");

            migrationBuilder.DropIndex(
                name: "IX_password_credentials_username_normalized",
                table: "password_credentials");

            migrationBuilder.DropIndex(
                name: "IX_login_attempts_username_normalized",
                table: "login_attempts");

            migrationBuilder.DropIndex(
                name: "IX_app_registrations_app_id_normalized",
                table: "app_registrations");

            migrationBuilder.AlterColumn<string>(
                name: "provider_name_normalized",
                table: "user_logins",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100);

            migrationBuilder.AlterColumn<string>(
                name: "username_normalized",
                table: "password_credentials",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100);

            migrationBuilder.AlterColumn<string>(
                name: "username_normalized",
                table: "login_attempts",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100);

            migrationBuilder.AlterColumn<string>(
                name: "app_id_normalized",
                table: "app_registrations",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(100)",
                oldMaxLength: 100);

            migrationBuilder.CreateIndex(
                name: "IX_user_logins_provider_name_provider_user_id",
                table: "user_logins",
                columns: new[] { "provider_name", "provider_user_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_password_credentials_username",
                table: "password_credentials",
                column: "username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_login_attempts_username",
                table: "login_attempts",
                column: "username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_registrations_app_id",
                table: "app_registrations",
                column: "app_id",
                unique: true);
        }
    }
}
