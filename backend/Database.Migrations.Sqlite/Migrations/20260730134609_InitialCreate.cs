using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "accounts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    is_active = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    remark = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    remark_normalized = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    nickname = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    nickname_normalized = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    last_login_at = table.Column<long>(type: "INTEGER", nullable: true),
                    last_login_ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    last_login_method = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    total_login_count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_accounts", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "app_registrations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    app_id = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    app_id_normalized = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    app_secret_hash = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    app_name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    callback_url = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    is_active = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    callback_expires_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_registrations", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "audit_logs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    action = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    target_type = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    target_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    actor_id = table.Column<Guid>(type: "TEXT", nullable: true),
                    actor_name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    before_snapshot = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: true),
                    after_snapshot = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: true),
                    description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    client_ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    correlation_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_logs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "login_attempts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    username = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    username_normalized = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    last_attempt_at = table.Column<long>(type: "INTEGER", nullable: false),
                    failed_attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    lockout_until = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_login_attempts", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "login_histories",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: true),
                    username = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    auth_method = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    event_type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    client_ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    user_agent = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    failure_reason = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    app_id = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    correlation_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_login_histories", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "otps",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    phone = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    code = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    lockout_until = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_otps", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "password_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    username = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    username_normalized = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    password_hash = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_password_credentials", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    token_value = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    is_revoked = table.Column<bool>(type: "INTEGER", nullable: false),
                    app_id = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_tokens", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "security_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    key_id = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    public_key_exponent = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    public_key_modulus = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    encrypted_private_key_params = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    encryption_salt = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    is_active = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_keys", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "user_logins",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    provider_name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    provider_name_normalized = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    provider_user_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_logins", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_app_registrations_app_id_normalized",
                table: "app_registrations",
                column: "app_id_normalized",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_action_created_at",
                table: "audit_logs",
                columns: new[] { "action", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_actor_id_created_at",
                table: "audit_logs",
                columns: new[] { "actor_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_created_at",
                table: "audit_logs",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_target_type_target_id_created_at",
                table: "audit_logs",
                columns: new[] { "target_type", "target_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_login_attempts_username_normalized",
                table: "login_attempts",
                column: "username_normalized",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_login_histories_account_id",
                table: "login_histories",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_login_histories_client_ip",
                table: "login_histories",
                column: "client_ip");

            migrationBuilder.CreateIndex(
                name: "IX_login_histories_created_at",
                table: "login_histories",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_otps_phone",
                table: "otps",
                column: "phone");

            migrationBuilder.CreateIndex(
                name: "IX_password_credentials_account_id",
                table: "password_credentials",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_password_credentials_username_normalized",
                table: "password_credentials",
                column: "username_normalized",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_token_value",
                table: "refresh_tokens",
                column: "token_value",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_keys_key_id",
                table: "security_keys",
                column: "key_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_user_logins_account_id",
                table: "user_logins",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_user_logins_provider_name_normalized_provider_user_id",
                table: "user_logins",
                columns: new[] { "provider_name_normalized", "provider_user_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "accounts");

            migrationBuilder.DropTable(
                name: "app_registrations");

            migrationBuilder.DropTable(
                name: "audit_logs");

            migrationBuilder.DropTable(
                name: "login_attempts");

            migrationBuilder.DropTable(
                name: "login_histories");

            migrationBuilder.DropTable(
                name: "otps");

            migrationBuilder.DropTable(
                name: "password_credentials");

            migrationBuilder.DropTable(
                name: "refresh_tokens");

            migrationBuilder.DropTable(
                name: "security_keys");

            migrationBuilder.DropTable(
                name: "user_logins");
        }
    }
}
