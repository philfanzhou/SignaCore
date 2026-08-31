using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class PersistInteractiveOidcClientConfiguration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "allow_authorization_code",
                table: "app_registrations",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "allow_refresh_token",
                table: "app_registrations",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "allowed_scopes",
                table: "app_registrations",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "openid");

            migrationBuilder.AddColumn<int>(
                name: "client_type",
                table: "app_registrations",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "identity_session_max_age_seconds",
                table: "app_registrations",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "app_redirect_uris",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "TEXT", nullable: false),
                    app_registration_id = table.Column<Guid>(type: "TEXT", nullable: false),
                    kind = table.Column<int>(type: "INTEGER", nullable: false),
                    canonical_uri = table.Column<string>(type: "TEXT", maxLength: 501, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_redirect_uris", x => x.id);
                    table.ForeignKey(
                        name: "FK_app_redirect_uris_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_app_redirect_uris_app_registration_id_kind_canonical_uri",
                table: "app_redirect_uris",
                columns: new[] { "app_registration_id", "kind", "canonical_uri" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "app_redirect_uris");

            migrationBuilder.DropColumn(
                name: "allow_authorization_code",
                table: "app_registrations");

            migrationBuilder.DropColumn(
                name: "allow_refresh_token",
                table: "app_registrations");

            migrationBuilder.DropColumn(
                name: "allowed_scopes",
                table: "app_registrations");

            migrationBuilder.DropColumn(
                name: "client_type",
                table: "app_registrations");

            migrationBuilder.DropColumn(
                name: "identity_session_max_age_seconds",
                table: "app_registrations");
        }
    }
}
