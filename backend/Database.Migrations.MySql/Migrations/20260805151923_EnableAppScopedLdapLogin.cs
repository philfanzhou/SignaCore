using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class EnableAppScopedLdapLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ldap_credential_id",
                table: "refresh_tokens",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.AddColumn<int>(
                name: "ldap_login_mode",
                table: "app_registrations",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "ldap_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    account_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    directory_key = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    directory_key_normalized = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    object_guid = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    user_principal_name = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    user_principal_name_normalized = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    sam_account_name = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    sam_account_name_normalized = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false, collation: "utf8mb4_bin")
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ldap_credentials", x => x.id);
                    table.ForeignKey(
                        name: "FK_ldap_credentials_accounts_account_id",
                        column: x => x.account_id,
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateTable(
                name: "app_ldap_accesses",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    app_registration_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    ldap_credential_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    approval_source = table.Column<int>(type: "int", nullable: false),
                    is_active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    approved_by = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_ldap_accesses", x => x.id);
                    table.ForeignKey(
                        name: "FK_app_ldap_accesses_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_app_ldap_accesses_ldap_credentials_ldap_credential_id",
                        column: x => x.ldap_credential_id,
                        principalTable: "ldap_credentials",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_ldap_credential_id",
                table: "refresh_tokens",
                column: "ldap_credential_id");

            migrationBuilder.CreateIndex(
                name: "IX_app_ldap_accesses_app_registration_id_ldap_credential_id",
                table: "app_ldap_accesses",
                columns: new[] { "app_registration_id", "ldap_credential_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_ldap_accesses_ldap_credential_id",
                table: "app_ldap_accesses",
                column: "ldap_credential_id");

            migrationBuilder.CreateIndex(
                name: "IX_ldap_credentials_account_id",
                table: "ldap_credentials",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_ldap_credentials_directory_key_normalized_object_guid",
                table: "ldap_credentials",
                columns: new[] { "directory_key_normalized", "object_guid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ldap_credentials_directory_key_normalized_sam_account_name_n~",
                table: "ldap_credentials",
                columns: new[] { "directory_key_normalized", "sam_account_name_normalized" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ldap_credentials_directory_key_normalized_user_principal_nam~",
                table: "ldap_credentials",
                columns: new[] { "directory_key_normalized", "user_principal_name_normalized" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "app_ldap_accesses");

            migrationBuilder.DropTable(
                name: "ldap_credentials");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_ldap_credential_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "ldap_credential_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "ldap_login_mode",
                table: "app_registrations");
        }
    }
}
