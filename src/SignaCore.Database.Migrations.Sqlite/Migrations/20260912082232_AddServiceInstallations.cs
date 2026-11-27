using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SignaCore.Database.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddServiceInstallations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "service_installations",
                columns: table => new
                {
                    service_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    status = table.Column<int>(type: "INTEGER", nullable: false),
                    created_at_utc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    completed_at_utc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    version = table.Column<int>(type: "INTEGER", nullable: false),
                    setup_code_generation = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0),
                    setup_code_digest = table.Column<string>(type: "TEXT", maxLength: 74, nullable: true),
                    setup_code_issued_at_utc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    setup_code_expires_at_utc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_installations", x => x.service_id);
                });

            // Fail-closed adoption (ServiceMantle issue #70). Seed a single Completed
            // `service_installations` row for service_id 'signacore' whenever the database is
            // anything other than a brand-new empty install, so that once a later task switches
            // startup phase resolution to read `service_installations`, an upgraded database is
            // never classified as PendingSetup and never re-exposes anonymous setup.
            //
            // Condition mirrors StateResolver: a Completed `installation_state`
            // singleton, OR any pre-existing business data (the same 9 tables HasBusinessDataAsync
            // probes). A Pending singleton with no business data, and a brand-new empty database,
            // correctly stay empty so anonymous setup remains open.
            //
            // status = 1 is Completed in both SignaCore's and ServiceMantle's InstallationStatus.
            // The timestamp is computed once in a derived table so created_at_utc == completed_at_utc,
            // satisfying the store mapper invariants (CreatedAtUtc != default, Completed implies
            // CompletedAtUtc >= CreatedAtUtc); it is stored as TEXT in EF Core's SQLite DateTime
            // format. The legacy setup-code hash is intentionally not carried over: a Completed row
            // holds no setup-code material, and the legacy hash format is not migratable.
            migrationBuilder.Sql(
                """
                INSERT INTO service_installations
                    (service_id, status, created_at_utc, completed_at_utc, version, setup_code_generation)
                SELECT 'signacore', 1, ts.now_utc, ts.now_utc, 1, 0
                FROM (SELECT strftime('%Y-%m-%d %H:%M:%f', 'now') AS now_utc) AS ts
                WHERE NOT EXISTS (
                          SELECT 1 FROM service_installations WHERE service_id = 'signacore')
                  AND (
                          EXISTS (SELECT 1 FROM installation_state WHERE id = 1 AND status = 1)
                       OR EXISTS (SELECT 1 FROM accounts)
                       OR EXISTS (SELECT 1 FROM password_credentials)
                       OR EXISTS (SELECT 1 FROM user_logins)
                       OR EXISTS (SELECT 1 FROM ldap_credentials)
                       OR EXISTS (SELECT 1 FROM app_registrations)
                       OR EXISTS (SELECT 1 FROM security_keys)
                       OR EXISTS (SELECT 1 FROM refresh_tokens)
                       OR EXISTS (SELECT 1 FROM audit_logs)
                       OR EXISTS (SELECT 1 FROM login_histories)
                  );
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "service_installations");
        }
    }
}
