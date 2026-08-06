using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "accounts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    remark = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    remark_normalized = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    nickname = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    nickname_normalized = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_login_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: true),
                    last_login_ip = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_login_method = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    total_login_count = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_accounts", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "app_registrations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    app_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    app_id_normalized = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    app_secret_hash = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    app_name = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    callback_url = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    callback_expires_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_registrations", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "audit_logs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    action = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    target_type = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    target_id = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    actor_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    actor_name = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    before_snapshot = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    after_snapshot = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    description = table.Column<string>(type: "varchar(1000)", maxLength: 1000, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    client_ip = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    correlation_id = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_logs", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "login_attempts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    username = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    username_normalized = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    last_attempt_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    failed_attempts = table.Column<int>(type: "int", nullable: false),
                    lockout_until = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_login_attempts", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "login_histories",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    account_id = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    username = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    auth_method = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    event_type = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    client_ip = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    user_agent = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    failure_reason = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    app_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    correlation_id = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_login_histories", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "otps",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    phone = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    code = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    expires_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    attempts = table.Column<int>(type: "int", nullable: false),
                    lockout_until = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_otps", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "password_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    account_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    username = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    username_normalized = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    password_hash = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_password_credentials", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    account_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    token_value = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    expires_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    is_revoked = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    app_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_tokens", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "security_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    key_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    public_key_exponent = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    public_key_modulus = table.Column<string>(type: "varchar(2048)", maxLength: 2048, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    encrypted_private_key_params = table.Column<string>(type: "varchar(4096)", maxLength: 4096, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    encryption_salt = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    expires_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_keys", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "user_logins",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    account_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    provider_name = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    provider_name_normalized = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    provider_user_id = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_logins", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

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
