using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddBrowserSmsLoginStorage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Browser SMS login storage (AC-15): PS-03 sms_code_send_count, the PS-04 SMS
            // reference with its auth-method CHECK, and the PS-24 oidc-sms-code policy. SQLite
            // cannot alter a column's nullability or a CHECK in place, so EF rebuilds
            // identity_sessions, authorization_requests, and oidc_rate_limit_buckets (copy into
            // ef_temp_*, foreign keys off, drop/rename, recreate every index). Every row and index
            // is preserved, and every existing session is a Password row that already satisfies
            // the new CHECK; only the physical column order follows EF's ordering afterwards.
            migrationBuilder.DropCheckConstraint(
                name: "CK_oidc_rate_limit_buckets_policy",
                table: "oidc_rate_limit_buckets");

            migrationBuilder.AlterColumn<Guid>(
                name: "password_credential_id",
                table: "identity_sessions",
                type: "TEXT",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "TEXT");

            migrationBuilder.AddColumn<Guid>(
                name: "sms_user_login_id",
                table: "identity_sessions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "sms_code_send_count",
                table: "authorization_requests",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddCheckConstraint(
                name: "CK_oidc_rate_limit_buckets_policy",
                table: "oidc_rate_limit_buckets",
                sql: "policy IN ('oidc-authorize', 'oidc-login', 'oidc-token', 'oidc-userinfo', 'oidc-logout', 'oidc-revoke', 'oidc-sms-code')");

            migrationBuilder.CreateIndex(
                name: "IX_identity_sessions_sms_user_login_id",
                table: "identity_sessions",
                column: "sms_user_login_id");

            migrationBuilder.AddCheckConstraint(
                name: "CK_identity_sessions_auth_method_reference",
                table: "identity_sessions",
                sql: "(auth_method = 'Password' AND password_credential_id IS NOT NULL AND sms_user_login_id IS NULL) OR (auth_method = 'Sms' AND sms_user_login_id IS NOT NULL AND password_credential_id IS NULL)");

            migrationBuilder.AddCheckConstraint(
                name: "CK_authorization_requests_sms_code_send_count",
                table: "authorization_requests",
                sql: "sms_code_send_count >= 0");

            migrationBuilder.AddForeignKey(
                name: "FK_identity_sessions_user_logins_sms_user_login_id",
                table: "identity_sessions",
                column: "sms_user_login_id",
                principalTable: "user_logins",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // The rollback gate runs first and changes nothing when it fails: a downgrade is only
            // safe while no Sms session (PS-04) and no oidc-sms-code bucket (PS-24) remain,
            // because the previous schema can represent neither. The TEMP table's CHECK rejects a
            // non-zero count, so the INSERT fails closed before any table is rebuilt. The count
            // column needs no gate.
            migrationBuilder.Sql("""
                CREATE TEMP TABLE ef_down_gate(sms_rows INTEGER NOT NULL CHECK (sms_rows = 0));
                INSERT INTO ef_down_gate
                SELECT (SELECT count(*) FROM identity_sessions
                        WHERE auth_method = 'Sms' OR sms_user_login_id IS NOT NULL)
                     + (SELECT count(*) FROM oidc_rate_limit_buckets WHERE policy = 'oidc-sms-code');
                DROP TABLE ef_down_gate;
                """);

            migrationBuilder.DropForeignKey(
                name: "FK_identity_sessions_user_logins_sms_user_login_id",
                table: "identity_sessions");

            migrationBuilder.DropCheckConstraint(
                name: "CK_oidc_rate_limit_buckets_policy",
                table: "oidc_rate_limit_buckets");

            migrationBuilder.DropIndex(
                name: "IX_identity_sessions_sms_user_login_id",
                table: "identity_sessions");

            migrationBuilder.DropCheckConstraint(
                name: "CK_identity_sessions_auth_method_reference",
                table: "identity_sessions");

            migrationBuilder.DropCheckConstraint(
                name: "CK_authorization_requests_sms_code_send_count",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "sms_user_login_id",
                table: "identity_sessions");

            migrationBuilder.DropColumn(
                name: "sms_code_send_count",
                table: "authorization_requests");

            // Behind the gate every remaining row is a Password row with a credential, so the
            // rebuilt column returns to NOT NULL without any IFNULL backfill or column default.
            migrationBuilder.AlterColumn<Guid>(
                name: "password_credential_id",
                table: "identity_sessions",
                type: "TEXT",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "TEXT",
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_oidc_rate_limit_buckets_policy",
                table: "oidc_rate_limit_buckets",
                sql: "policy IN ('oidc-authorize', 'oidc-login', 'oidc-token', 'oidc-userinfo', 'oidc-logout', 'oidc-revoke')");
        }
    }
}
