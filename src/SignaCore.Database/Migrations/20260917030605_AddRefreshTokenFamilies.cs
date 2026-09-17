using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenFamilies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // 1. The six family columns arrive as nullable, so every existing row keeps its
            // current values byte for byte and no default touches a stored token value.
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "auth_time",
                table: "refresh_tokens",
                type: "timestamptz",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "consumed_at",
                table: "refresh_tokens",
                type: "timestamptz",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "family_id",
                table: "refresh_tokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "identity_session_id",
                table: "refresh_tokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "parent_id",
                table: "refresh_tokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "scope",
                table: "refresh_tokens",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            // 2. One bounded statement makes every existing row the singleton root of its own
            // family (PS-07). It reads and writes only id columns — never token_value (DF-09).
            migrationBuilder.Sql("UPDATE refresh_tokens SET family_id = id WHERE family_id IS NULL;");

            // 3. Only after the backfill succeeds does family_id become non-nullable.
            migrationBuilder.AlterColumn<Guid>(
                name: "family_id",
                table: "refresh_tokens",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            // 4. Indexes, checks, and the three refresh_tokens references.
            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_family_id",
                table: "refresh_tokens",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_identity_session_id",
                table: "refresh_tokens",
                column: "identity_session_id");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_parent_id",
                table: "refresh_tokens",
                column: "parent_id",
                unique: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_refresh_tokens_family_marker",
                table: "refresh_tokens",
                sql: "(identity_session_id IS NULL AND scope IS NULL AND auth_time IS NULL AND consumed_at IS NULL AND parent_id IS NULL) OR (identity_session_id IS NOT NULL AND scope IS NOT NULL AND auth_time IS NOT NULL)");

            migrationBuilder.AddCheckConstraint(
                name: "CK_refresh_tokens_family_shape",
                table: "refresh_tokens",
                sql: "(family_id = id AND parent_id IS NULL) OR (family_id <> id AND parent_id IS NOT NULL AND parent_id <> id)");

            migrationBuilder.AddForeignKey(
                name: "FK_refresh_tokens_identity_sessions_identity_session_id",
                table: "refresh_tokens",
                column: "identity_session_id",
                principalTable: "identity_sessions",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_refresh_tokens_refresh_tokens_family_id",
                table: "refresh_tokens",
                column: "family_id",
                principalTable: "refresh_tokens",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_refresh_tokens_refresh_tokens_parent_id",
                table: "refresh_tokens",
                column: "parent_id",
                principalTable: "refresh_tokens",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            // 5. Last, after every existing token has a traceable root, the single deferred
            // PS-23 reference: authorization_codes.refresh_family_id resolves the family root.
            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_refresh_family_id",
                table: "authorization_codes",
                column: "refresh_family_id");

            migrationBuilder.AddForeignKey(
                name: "FK_authorization_codes_refresh_tokens_refresh_family_id",
                table: "authorization_codes",
                column: "refresh_family_id",
                principalTable: "refresh_tokens",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // The rollback gate runs first and changes nothing when it fails: a downgrade is
            // only safe while no interactive row and no code-to-root link exist (AC-11).
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM refresh_tokens WHERE identity_session_id IS NOT NULL
                    ) OR EXISTS (
                        SELECT 1 FROM authorization_codes WHERE refresh_family_id IS NOT NULL
                    ) THEN
                        RAISE EXCEPTION 'refresh family downgrade blocked: interactive rows exist';
                    END IF;
                END $$;
                """);

            migrationBuilder.DropForeignKey(
                name: "FK_authorization_codes_refresh_tokens_refresh_family_id",
                table: "authorization_codes");

            migrationBuilder.DropIndex(
                name: "IX_authorization_codes_refresh_family_id",
                table: "authorization_codes");

            migrationBuilder.DropForeignKey(
                name: "FK_refresh_tokens_identity_sessions_identity_session_id",
                table: "refresh_tokens");

            migrationBuilder.DropForeignKey(
                name: "FK_refresh_tokens_refresh_tokens_family_id",
                table: "refresh_tokens");

            migrationBuilder.DropForeignKey(
                name: "FK_refresh_tokens_refresh_tokens_parent_id",
                table: "refresh_tokens");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_family_id",
                table: "refresh_tokens");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_identity_session_id",
                table: "refresh_tokens");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_parent_id",
                table: "refresh_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_refresh_tokens_family_marker",
                table: "refresh_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_refresh_tokens_family_shape",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "auth_time",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "consumed_at",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "family_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "identity_session_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "parent_id",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "scope",
                table: "refresh_tokens");
        }
    }
}
