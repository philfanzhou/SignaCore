using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddOidcRateLimitBuckets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "oidc_rate_limit_buckets",
                columns: table => new
                {
                    policy = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    partition_digest = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    window_expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    permit_count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oidc_rate_limit_buckets", x => new { x.policy, x.partition_digest });
                    table.CheckConstraint("CK_oidc_rate_limit_buckets_digest_length", "length(partition_digest) = 64");
                    table.CheckConstraint("CK_oidc_rate_limit_buckets_permit_count", "permit_count BETWEEN 1 AND 90");
                    table.CheckConstraint("CK_oidc_rate_limit_buckets_policy", "policy IN ('oidc-authorize', 'oidc-login', 'oidc-token', 'oidc-userinfo', 'oidc-logout', 'oidc-revoke')");
                });

            migrationBuilder.CreateIndex(
                name: "IX_oidc_rate_limit_buckets_window_expires_at",
                table: "oidc_rate_limit_buckets",
                column: "window_expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "oidc_rate_limit_buckets");
        }
    }
}
