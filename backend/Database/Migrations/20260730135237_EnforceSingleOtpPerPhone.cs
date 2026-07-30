using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations
{
    /// <inheritdoc />
    public partial class EnforceSingleOtpPerPhone : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_otps_phone",
                table: "otps");

            migrationBuilder.CreateIndex(
                name: "IX_otps_phone",
                table: "otps",
                column: "phone",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_otps_phone",
                table: "otps");

            migrationBuilder.CreateIndex(
                name: "IX_otps_phone",
                table: "otps",
                column: "phone");
        }
    }
}
