/**
 * Assembles the complete connection strings the shared bootstrap entries accept.
 *
 * Every structured value is quoted — internal double quotes doubled — so any character survives
 * the round trip through Npgsql's or SQLite's connection-string parser verbatim: semicolons,
 * equals signs, leading single quotes, embedded double quotes, surrounding spaces, and non-ASCII
 * input all stay exactly what the operator typed. The advanced mode passes a raw string through
 * unchanged instead.
 */

/** Wraps one structured value in double quotes and doubles its embedded double quotes. */
export function escapeConnectionStringValue(value: string): string {
  return `"${value.replaceAll('"', '""')}"`
}

export interface PostgreSqlConnectionStringFields {
  host: string
  port: number | null
  database: string
  username: string
  password: string
}

export function buildPostgreSqlConnectionString(fields: PostgreSqlConnectionStringFields): string {
  const port = fields.port ?? 5432
  return [
    `Host=${escapeConnectionStringValue(fields.host)}`,
    `Port=${port}`,
    `Database=${escapeConnectionStringValue(fields.database)}`,
    `Username=${escapeConnectionStringValue(fields.username)}`,
    `Password=${escapeConnectionStringValue(fields.password)}`,
  ].join(';')
}

export function buildSqliteConnectionString(filePath: string): string {
  return `Data Source=${escapeConnectionStringValue(filePath)}`
}
