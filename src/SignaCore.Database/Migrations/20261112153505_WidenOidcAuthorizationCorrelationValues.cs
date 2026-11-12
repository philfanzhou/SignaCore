using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations
{
    /// <inheritdoc />
    public partial class WidenOidcAuthorizationCorrelationValues : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "state",
                table: "authorization_requests",
                type: "character varying(2048)",
                maxLength: 2048,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "nonce",
                table: "authorization_requests",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(128)",
                oldMaxLength: 128);

            migrationBuilder.AlterColumn<string>(
                name: "nonce",
                table: "authorization_codes",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(128)",
                oldMaxLength: 128);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Hold the locks through the ALTERs so no writer can insert a value after the check.
            // In particular, PostgreSQL can silently discard excess trailing spaces on narrowing.
            migrationBuilder.Sql("""
                LOCK TABLE authorization_requests, authorization_codes IN ACCESS EXCLUSIVE MODE;
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM authorization_requests
                        WHERE char_length(state) > 128 OR char_length(nonce) > 128
                    ) OR EXISTS (
                        SELECT 1 FROM authorization_codes WHERE char_length(nonce) > 128
                    ) THEN
                        RAISE EXCEPTION 'OIDC authorization downgrade blocked: state or nonce exceeds 128 characters';
                    END IF;
                END $$;
                """);

            migrationBuilder.AlterColumn<string>(
                name: "state",
                table: "authorization_requests",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(2048)",
                oldMaxLength: 2048);

            migrationBuilder.AlterColumn<string>(
                name: "nonce",
                table: "authorization_requests",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(1024)",
                oldMaxLength: 1024);

            migrationBuilder.AlterColumn<string>(
                name: "nonce",
                table: "authorization_codes",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(1024)",
                oldMaxLength: 1024);
        }
    }
}
