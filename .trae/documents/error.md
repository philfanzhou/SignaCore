sudo ./start.sh
c2fc6492f5533726ac5523b470065521882a29d551acf2bd4cb1e584a27310cb

QuantumZhou.Identity Unified Service Started
  HTTP Port: 10891 (Admin Web)
  Network: ruoyu-net
  DB: ruoyu-postgres:5432/ruoyu_identity
=== Real-time Logs ===
2026-05-02T16:11:59.396923609Z {"Timestamp":"2026-05-03T00:11:59.360Z","EventId":0,"LogLevel":"Information","Category":"QuantumZhou.Identity.Host","Message":"Service endpoints configured: gRPC=5001, HTTP=5002","State":{"Message":"Service endpoints configured: gRPC=5001, HTTP=5002","GrpcPort":5001,"HttpPort":5002,"{OriginalFormat}":"Service endpoints configured: gRPC={GrpcPort}, HTTP={HttpPort}"},"Scopes":[]}
2026-05-02T16:12:00.606339322Z {"Timestamp":"2026-05-03T00:12:00.605Z","EventId":0,"LogLevel":"Information","Category":"QuantumZhou.Identity.Host","Message":"Applying 1 pending migrations...","State":{"Message":"Applying 1 pending migrations...","Count":1,"{OriginalFormat}":"Applying {Count} pending migrations..."},"Scopes":[]}
2026-05-02T16:12:00.744782853Z {"Timestamp":"2026-05-03T00:12:00.741Z","EventId":20102,"LogLevel":"Error","Category":"Microsoft.EntityFrameworkCore.Database.Command","Message":"Failed executing DbCommand (7ms) [Parameters=[], CommandType=\u0027Text\u0027, CommandTimeout=\u002730\u0027]\nALTER TABLE accounts ALTER COLUMN is_active TYPE boolean USING (is_active != 0)","State":{"Message":"Failed executing DbCommand (7ms) [Parameters=[], CommandType=\u0027Text\u0027, CommandTimeout=\u002730\u0027]\nALTER TABLE accounts ALTER COLUMN is_active TYPE boolean USING (is_active != 0)","elapsed":"7","parameters":"","commandType":"Text","commandTimeout":30,"newLine":"\n","commandText":"ALTER TABLE accounts ALTER COLUMN is_active TYPE boolean USING (is_active != 0)","{OriginalFormat}":"Failed executing DbCommand ({elapsed}ms) [Parameters=[{parameters}], CommandType=\u0027{commandType}\u0027, CommandTimeout=\u0027{commandTimeout}\u0027]{newLine}{commandText}"},"Scopes":[]}
2026-05-02T16:12:00.772914867Z {"Timestamp":"2026-05-03T00:12:00.752Z","EventId":0,"LogLevel":"Error","Category":"QuantumZhou.Identity.Host","Message":"Database initialization failed","Exception":"Npgsql.PostgresException (0x80004005): 42883: operator does not exist: boolean \u003C\u003E integer\n\nPOSITION: 75\n   at Npgsql.Internal.NpgsqlConnector.ReadMessageLong(Boolean async, DataRowLoadingMode dataRowLoadingMode, Boolean readingNotifications, Boolean isReadingPrependedMessage)\n   at System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder\u00601.StateMachineBox\u00601.System.Threading.Tasks.Sources.IValueTaskSource\u003CTResult\u003E.GetResult(Int16 token)\n   at Npgsql.NpgsqlDataReader.NextResult(Boolean async, Boolean isConsuming, CancellationToken cancellationToken)\n   at Npgsql.NpgsqlDataReader.NextResult(Boolean async, Boolean isConsuming, CancellationToken cancellationToken)\n   at Npgsql.NpgsqlDataReader.NextResult()\n   at Npgsql.NpgsqlCommand.ExecuteReader(Boolean async, CommandBehavior behavior, CancellationToken cancellationToken)\n   at Npgsql.NpgsqlCommand.ExecuteReader(Boolean async, CommandBehavior behavior, CancellationToken cancellationToken)\n   at Npgsql.NpgsqlCommand.ExecuteNonQuery(Boolean async, CancellationToken cancellationToken)\n   at Npgsql.NpgsqlCommand.ExecuteNonQuery()\n   at Microsoft.EntityFrameworkCore.Storage.RelationalCommand.ExecuteNonQuery(RelationalCommandParameterObject parameterObject)\n   at Microsoft.EntityFrameworkCore.Migrations.MigrationCommand.ExecuteNonQuery(IRelationalConnection connection, IReadOnlyDictionary\u00602 parameterValues)\n   at Microsoft.EntityFrameworkCore.Migrations.Internal.MigrationCommandExecutor.ExecuteNonQuery(IEnumerable\u00601 migrationCommands, IRelationalConnection connection)\n   at Microsoft.EntityFrameworkCore.Migrations.Internal.Migrator.Migrate(String targetMigration)\n   at Npgsql.EntityFrameworkCore.PostgreSQL.Migrations.Internal.NpgsqlMigrator.Migrate(String targetMigration)\n   at Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.Migrate(DatabaseFacade databaseFacade)\n   at Program.\u003CMain\u003E$(String[] args) in /src/backend/Host/Program.cs:line 458\n  Exception data:\n    Severity: ERROR\n    SqlState: 42883\n    MessageText: operator does not exist: boolean \u003C\u003E integer\n    Hint: No operator matches the given name and argument types. You might need to add explicit type casts.\n    Position: 75\n    File: parse_oper.c\n    Line: 647\n    Routine: op_error","State":{"Message":"Database initialization failed","{OriginalFormat}":"Database initialization failed"},"Scopes":[]}
2026-05-02T16:12:00.781224323Z Unhandled exception. Npgsql.PostgresException (0x80004005): 42883: operator does not exist: boolean <> integer
2026-05-02T16:12:00.781264880Z
2026-05-02T16:12:00.781271733Z POSITION: 75
2026-05-02T16:12:00.781276572Z    at Npgsql.Internal.NpgsqlConnector.ReadMessageLong(Boolean async, DataRowLoadingMode dataRowLoadingMode, Boolean readingNotifications, Boolean isReadingPrependedMessage)
2026-05-02T16:12:00.781281180Z    at System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder`1.StateMachineBox`1.System.Threading.Tasks.Sources.IValueTaskSource<TResult>.GetResult(Int16 token)
2026-05-02T16:12:00.781286310Z    at Npgsql.NpgsqlDataReader.NextResult(Boolean async, Boolean isConsuming, CancellationToken cancellationToken)
2026-05-02T16:12:00.781290919Z    at Npgsql.NpgsqlDataReader.NextResult(Boolean async, Boolean isConsuming, CancellationToken cancellationToken)
2026-05-02T16:12:00.781295587Z    at Npgsql.NpgsqlDataReader.NextResult()
2026-05-02T16:12:00.781300046Z    at Npgsql.NpgsqlCommand.ExecuteReader(Boolean async, CommandBehavior behavior, CancellationToken cancellationToken)
2026-05-02T16:12:00.781304715Z    at Npgsql.NpgsqlCommand.ExecuteReader(Boolean async, CommandBehavior behavior, CancellationToken cancellationToken)
2026-05-02T16:12:00.781309283Z    at Npgsql.NpgsqlCommand.ExecuteNonQuery(Boolean async, CancellationToken cancellationToken)
2026-05-02T16:12:00.781313591Z    at Npgsql.NpgsqlCommand.ExecuteNonQuery()
2026-05-02T16:12:00.781365018Z    at Microsoft.EntityFrameworkCore.Storage.RelationalCommand.ExecuteNonQuery(RelationalCommandParameterObject parameterObject)
2026-05-02T16:12:00.781371560Z    at Microsoft.EntityFrameworkCore.Migrations.MigrationCommand.ExecuteNonQuery(IRelationalConnection connection, IReadOnlyDictionary`2 parameterValues)
2026-05-02T16:12:00.781376379Z    at Microsoft.EntityFrameworkCore.Migrations.Internal.MigrationCommandExecutor.ExecuteNonQuery(IEnumerable`1 migrationCommands, IRelationalConnection connection)
2026-05-02T16:12:00.781381178Z    at Microsoft.EntityFrameworkCore.Migrations.Internal.Migrator.Migrate(String targetMigration)
2026-05-02T16:12:00.781385396Z    at Npgsql.EntityFrameworkCore.PostgreSQL.Migrations.Internal.NpgsqlMigrator.Migrate(String targetMigration)
2026-05-02T16:12:00.781389805Z    at Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.Migrate(DatabaseFacade databaseFacade)
2026-05-02T16:12:00.781394053Z    at Program.<Main>$(String[] args) in /src/backend/Host/Program.cs:line 458
2026-05-02T16:12:00.781398551Z    at Program.<Main>(String[] args)
2026-05-02T16:12:00.781402809Z   Exception data:
2026-05-02T16:12:00.781423408Z     Severity: ERROR
2026-05-02T16:12:00.781427716Z     SqlState: 42883
2026-05-02T16:12:00.781434439Z     MessageText: operator does not exist: boolean <> integer
2026-05-02T16:12:00.781439157Z     Hint: No operator matches the given name and argument types. You might need to add explicit type casts.
2026-05-02T16:12:00.781443586Z     Position: 75
2026-05-02T16:12:00.781447693Z     File: parse_oper.c
2026-05-02T16:12:00.781451881Z     Line: 647
2026-05-02T16:12:00.781456019Z     Routine: op_error
phil@deb-zhiyuan-05:/mnt/data1/docker/ruoyu/identity$