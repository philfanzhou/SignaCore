using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddIdentitySessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "identity_sessions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    password_credential_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    auth_method = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    auth_time = table.Column<long>(type: "INTEGER", nullable: false),
                    last_seen_at = table.Column<long>(type: "INTEGER", nullable: false),
                    idle_expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    absolute_expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: true),
                    revocation_reason = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identity_sessions", x => x.id);
                    table.CheckConstraint("CK_identity_sessions_revocation_pair", "(revoked_at IS NULL AND revocation_reason IS NULL) OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_identity_sessions_accounts_account_id",
                        column: x => x.account_id,
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_identity_sessions_password_credentials_password_credential_id",
                        column: x => x.password_credential_id,
                        principalTable: "password_credentials",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_identity_sessions_account_id",
                table: "identity_sessions",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_identity_sessions_password_credential_id",
                table: "identity_sessions",
                column: "password_credential_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identity_sessions");
        }
    }
}
