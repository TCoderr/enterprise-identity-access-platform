using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Halka.DemoClient.Migrations
{
    /// <inheritdoc />
    public partial class InitialAppSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "app_sessions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    subject = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    protected_tokens = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    version = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_app_sessions", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_app_sessions_subject",
                table: "app_sessions",
                column: "subject");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "app_sessions");
        }
    }
}
