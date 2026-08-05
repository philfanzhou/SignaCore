using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations.Sqlite.Migrations
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
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ldap_login_mode",
                table: "app_registrations",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "ldap_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    directory_key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    directory_key_normalized = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    object_guid = table.Column<Guid>(type: "TEXT", nullable: false),
                    user_principal_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    user_principal_name_normalized = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    sam_account_name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    sam_account_name_normalized = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
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
                });

            migrationBuilder.CreateTable(
                name: "app_ldap_accesses",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    app_registration_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ldap_credential_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    approval_source = table.Column<int>(type: "INTEGER", nullable: false),
                    is_active = table.Column<bool>(type: "INTEGER", nullable: false),
                    approved_by = table.Column<Guid>(type: "TEXT", nullable: true),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false)
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
                });

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
                name: "IX_ldap_credentials_directory_key_normalized_sam_account_name_normalized",
                table: "ldap_credentials",
                columns: new[] { "directory_key_normalized", "sam_account_name_normalized" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ldap_credentials_directory_key_normalized_user_principal_name_normalized",
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
