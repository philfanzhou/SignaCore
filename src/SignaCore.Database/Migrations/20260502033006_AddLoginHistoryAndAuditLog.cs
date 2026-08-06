using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddLoginHistoryAndAuditLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "last_login_at",
                table: "accounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "last_login_ip",
                table: "accounts",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "last_login_method",
                table: "accounts",
                type: "TEXT",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "total_login_count",
                table: "accounts",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

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
                    created_at = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_logs", x => x.id);
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
                    created_at = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_login_histories", x => x.id);
                });

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
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_logs");

            migrationBuilder.DropTable(
                name: "login_histories");

            migrationBuilder.DropColumn(
                name: "last_login_at",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "last_login_ip",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "last_login_method",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "total_login_count",
                table: "accounts");
        }
    }
}
