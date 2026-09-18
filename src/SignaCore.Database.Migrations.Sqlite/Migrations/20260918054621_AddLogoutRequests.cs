using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    /// <remarks>
    /// Additive only: the <c>logout_requests</c> table of <c>PS-08</c> (SignaCore issue #68). The
    /// single referential constraint is the restrictive client reference; the account and session
    /// values are snapshots the completion compares against live rows, so no referential
    /// constraint may forbid a session row disappearing before its logout request does.
    /// </remarks>
    public partial class AddLogoutRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "logout_requests",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    handle_digest = table.Column<string>(type: "TEXT", maxLength: 71, nullable: false),
                    app_registration_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    account_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    identity_session_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    post_logout_redirect_uri = table.Column<string>(type: "TEXT", maxLength: 501, nullable: true),
                    state = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    consumed_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_logout_requests", x => x.id);
                    table.ForeignKey(
                        name: "FK_logout_requests_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_logout_requests_app_registration_id",
                table: "logout_requests",
                column: "app_registration_id");

            migrationBuilder.CreateIndex(
                name: "IX_logout_requests_handle_digest",
                table: "logout_requests",
                column: "handle_digest",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "logout_requests");
        }
    }
}
