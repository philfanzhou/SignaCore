using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddManagementBearerSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "management_bearer_sessions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    token_digest = table.Column<string>(type: "TEXT", maxLength: 71, nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_management_bearer_sessions", x => x.id);
                    table.CheckConstraint("CK_management_bearer_sessions_digest_length", "length(token_digest) = 71");
                    table.CheckConstraint("CK_management_bearer_sessions_expiry", "expires_at > created_at");
                    table.CheckConstraint("CK_management_bearer_sessions_revocation", "revoked_at IS NULL OR revoked_at >= created_at");
                    table.ForeignKey(
                        name: "FK_management_bearer_sessions_accounts_account_id",
                        column: x => x.account_id,
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_management_bearer_sessions_account_id",
                table: "management_bearer_sessions",
                column: "account_id");

            migrationBuilder.CreateIndex(
                name: "IX_management_bearer_sessions_expires_at",
                table: "management_bearer_sessions",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_management_bearer_sessions_token_digest",
                table: "management_bearer_sessions",
                column: "token_digest",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "management_bearer_sessions");
        }
    }
}
