using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddBrowserSmsLoginStorage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Browser SMS login storage (AC-15): PS-03 sms_code_send_count, the PS-04 SMS
            // reference with its auth-method CHECK, and the PS-24 oidc-sms-code policy. Every
            // step is an in-place ALTER inside the migration transaction; every existing session
            // is a Password row and already satisfies the new CHECK, and the count column's
            // database default keeps an older binary's continuation inserts valid during a
            // rolling upgrade.
            migrationBuilder.DropCheckConstraint(
                name: "CK_oidc_rate_limit_buckets_policy",
                table: "oidc_rate_limit_buckets");

            migrationBuilder.AlterColumn<Guid>(
                name: "password_credential_id",
                table: "identity_sessions",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<Guid>(
                name: "sms_user_login_id",
                table: "identity_sessions",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "sms_code_send_count",
                table: "authorization_requests",
                type: "integer",
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
            // because the previous schema can represent neither. The count column needs no gate.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM identity_sessions
                        WHERE auth_method = 'Sms' OR sms_user_login_id IS NOT NULL
                    ) OR EXISTS (
                        SELECT 1 FROM oidc_rate_limit_buckets WHERE policy = 'oidc-sms-code'
                    ) THEN
                        RAISE EXCEPTION 'browser SMS storage downgrade blocked: Sms sessions or oidc-sms-code buckets exist';
                    END IF;
                END $$;
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
            // column returns to NOT NULL without any backfill and without a column default.
            migrationBuilder.AlterColumn<Guid>(
                name: "password_credential_id",
                table: "identity_sessions",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_oidc_rate_limit_buckets_policy",
                table: "oidc_rate_limit_buckets",
                sql: "policy IN ('oidc-authorize', 'oidc-login', 'oidc-token', 'oidc-userinfo', 'oidc-logout', 'oidc-revoke')");
        }
    }
}
