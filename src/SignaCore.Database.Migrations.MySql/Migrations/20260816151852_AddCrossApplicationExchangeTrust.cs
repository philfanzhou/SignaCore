using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddCrossApplicationExchangeTrust : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "source_app_id",
                table: "refresh_tokens",
                type: "varchar(100)",
                maxLength: 100,
                nullable: true,
                collation: "utf8mb4_bin")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "app_exchange_trusts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    app_registration_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    source_app_registration_id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    approved_by = table.Column<Guid>(type: "char(36)", nullable: true, collation: "ascii_general_ci"),
                    created_at = table.Column<DateTime>(type: "datetime(6)", precision: 6, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_exchange_trusts", x => x.id);
                    table.CheckConstraint("CK_app_exchange_trusts_no_self_trust", "app_registration_id <> source_app_registration_id");
                    table.ForeignKey(
                        name: "FK_app_exchange_trusts_app_registrations_app_registration_id",
                        column: x => x.app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_app_exchange_trusts_app_registrations_source_app_registratio~",
                        column: x => x.source_app_registration_id,
                        principalTable: "app_registrations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4")
                .Annotation("Relational:Collation", "utf8mb4_bin");

            migrationBuilder.CreateIndex(
                name: "IX_app_exchange_trusts_app_registration_id_source_app_registrat~",
                table: "app_exchange_trusts",
                columns: new[] { "app_registration_id", "source_app_registration_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_app_exchange_trusts_source_app_registration_id",
                table: "app_exchange_trusts",
                column: "source_app_registration_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "app_exchange_trusts");

            migrationBuilder.DropColumn(
                name: "source_app_id",
                table: "refresh_tokens");
        }
    }
}
