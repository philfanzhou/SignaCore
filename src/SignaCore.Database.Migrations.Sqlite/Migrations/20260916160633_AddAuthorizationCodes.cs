using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthorizationCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "authorization_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    code_digest = table.Column<string>(type: "TEXT", maxLength: 71, nullable: false),
                    app_registration_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    identity_session_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    redirect_uri = table.Column<string>(type: "TEXT", maxLength: 501, nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    nonce = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    code_challenge = table.Column<string>(type: "TEXT", maxLength: 43, nullable: false),
                    auth_time = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    consumed_at = table.Column<long>(type: "INTEGER", nullable: true),
                    refresh_family_id = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authorization_codes", x => x.id);
                    table.CheckConstraint("CK_authorization_codes_family_requires_consumption", "refresh_family_id IS NULL OR consumed_at IS NOT NULL");
                    table.ForeignKey(
                        name: "FK_authorization_codes_accounts_account_id",
                        column: x => x.account_id,
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_authorization_codes_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_authorization_codes_identity_sessions_identity_session_id",
                        column: x => x.identity_session_id,
                        principalTable: "identity_sessions",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_account_id",
                table: "authorization_codes",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_app_registration_id",
                table: "authorization_codes",
                column: "app_registration_id");

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_code_digest",
                table: "authorization_codes",
                column: "code_digest",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_identity_session_id",
                table: "authorization_codes",
                column: "identity_session_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authorization_codes");
        }
    }
}
