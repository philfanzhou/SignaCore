using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace QuantumZhou.Identity.Database.Migrations
{
    public partial class FixTimestampColumnTypes : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'accounts' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE accounts ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'accounts' AND column_name = 'is_active' AND data_type = 'integer') THEN
        ALTER TABLE accounts ALTER COLUMN is_active TYPE boolean USING (is_active != 0);
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'accounts' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE accounts ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'accounts' AND column_name = 'last_login_at' AND data_type = 'text') THEN
        ALTER TABLE accounts ALTER COLUMN last_login_at TYPE timestamptz USING last_login_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'accounts' AND column_name = 'total_login_count' AND data_type = 'text') THEN
        ALTER TABLE accounts ALTER COLUMN total_login_count TYPE integer USING total_login_count::integer;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_credentials' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE password_credentials ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_credentials' AND column_name = 'account_id' AND data_type = 'text') THEN
        ALTER TABLE password_credentials ALTER COLUMN account_id TYPE uuid USING account_id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_credentials' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE password_credentials ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'user_logins' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE user_logins ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'user_logins' AND column_name = 'account_id' AND data_type = 'text') THEN
        ALTER TABLE user_logins ALTER COLUMN account_id TYPE uuid USING account_id::uuid;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'refresh_tokens' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE refresh_tokens ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'refresh_tokens' AND column_name = 'account_id' AND data_type = 'text') THEN
        ALTER TABLE refresh_tokens ALTER COLUMN account_id TYPE uuid USING account_id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'refresh_tokens' AND column_name = 'expires_at' AND data_type = 'text') THEN
        ALTER TABLE refresh_tokens ALTER COLUMN expires_at TYPE timestamptz USING expires_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'refresh_tokens' AND column_name = 'is_revoked' AND data_type = 'integer') THEN
        ALTER TABLE refresh_tokens ALTER COLUMN is_revoked TYPE boolean USING (is_revoked != 0);
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'refresh_tokens' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE refresh_tokens ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'app_registrations' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE app_registrations ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'app_registrations' AND column_name = 'is_active' AND data_type = 'integer') THEN
        ALTER TABLE app_registrations ALTER COLUMN is_active TYPE boolean USING (is_active != 0);
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'app_registrations' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE app_registrations ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'app_registrations' AND column_name = 'callback_expires_at' AND data_type = 'text') THEN
        ALTER TABLE app_registrations ALTER COLUMN callback_expires_at TYPE timestamptz USING callback_expires_at::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_keys' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE security_keys ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_keys' AND column_name = 'is_active' AND data_type = 'integer') THEN
        ALTER TABLE security_keys ALTER COLUMN is_active TYPE boolean USING (is_active != 0);
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_keys' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE security_keys ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_keys' AND column_name = 'expires_at' AND data_type = 'text') THEN
        ALTER TABLE security_keys ALTER COLUMN expires_at TYPE timestamptz USING expires_at::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'otps' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE otps ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'otps' AND column_name = 'expires_at' AND data_type = 'text') THEN
        ALTER TABLE otps ALTER COLUMN expires_at TYPE timestamptz USING expires_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'otps' AND column_name = 'lockout_until' AND data_type = 'text') THEN
        ALTER TABLE otps ALTER COLUMN lockout_until TYPE timestamptz USING lockout_until::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'otps' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE otps ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'login_attempts' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE login_attempts ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'login_attempts' AND column_name = 'last_attempt_at' AND data_type = 'text') THEN
        ALTER TABLE login_attempts ALTER COLUMN last_attempt_at TYPE timestamptz USING last_attempt_at::timestamptz;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'login_attempts' AND column_name = 'lockout_until' AND data_type = 'text') THEN
        ALTER TABLE login_attempts ALTER COLUMN lockout_until TYPE timestamptz USING lockout_until::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'login_histories' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE login_histories ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'login_histories' AND column_name = 'account_id' AND data_type = 'text') THEN
        ALTER TABLE login_histories ALTER COLUMN account_id TYPE uuid USING account_id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'login_histories' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE login_histories ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'audit_logs' AND column_name = 'id' AND data_type = 'text') THEN
        ALTER TABLE audit_logs ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'audit_logs' AND column_name = 'actor_id' AND data_type = 'text') THEN
        ALTER TABLE audit_logs ALTER COLUMN actor_id TYPE uuid USING actor_id::uuid;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'audit_logs' AND column_name = 'created_at' AND data_type = 'text') THEN
        ALTER TABLE audit_logs ALTER COLUMN created_at TYPE timestamptz USING created_at::timestamptz;
    END IF;
END $$;
");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
ALTER TABLE accounts ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE accounts ALTER COLUMN is_active TYPE INTEGER USING (CASE WHEN is_active THEN 1 ELSE 0 END);
ALTER TABLE accounts ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;
ALTER TABLE accounts ALTER COLUMN last_login_at TYPE TEXT USING last_login_at::TEXT;
ALTER TABLE accounts ALTER COLUMN total_login_count TYPE INTEGER;

ALTER TABLE password_credentials ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE password_credentials ALTER COLUMN account_id TYPE TEXT USING account_id::TEXT;
ALTER TABLE password_credentials ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;

ALTER TABLE user_logins ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE user_logins ALTER COLUMN account_id TYPE TEXT USING account_id::TEXT;

ALTER TABLE refresh_tokens ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE refresh_tokens ALTER COLUMN account_id TYPE TEXT USING account_id::TEXT;
ALTER TABLE refresh_tokens ALTER COLUMN expires_at TYPE TEXT USING expires_at::TEXT;
ALTER TABLE refresh_tokens ALTER COLUMN is_revoked TYPE INTEGER USING (CASE WHEN is_revoked THEN 1 ELSE 0 END);
ALTER TABLE refresh_tokens ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;

ALTER TABLE app_registrations ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE app_registrations ALTER COLUMN is_active TYPE INTEGER USING (CASE WHEN is_active THEN 1 ELSE 0 END);
ALTER TABLE app_registrations ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;
ALTER TABLE app_registrations ALTER COLUMN callback_expires_at TYPE TEXT USING callback_expires_at::TEXT;

ALTER TABLE security_keys ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE security_keys ALTER COLUMN is_active TYPE INTEGER USING (CASE WHEN is_active THEN 1 ELSE 0 END);
ALTER TABLE security_keys ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;
ALTER TABLE security_keys ALTER COLUMN expires_at TYPE TEXT USING expires_at::TEXT;

ALTER TABLE otps ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE otps ALTER COLUMN expires_at TYPE TEXT USING expires_at::TEXT;
ALTER TABLE otps ALTER COLUMN lockout_until TYPE TEXT USING lockout_until::TEXT;
ALTER TABLE otps ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;

ALTER TABLE login_attempts ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE login_attempts ALTER COLUMN last_attempt_at TYPE TEXT USING last_attempt_at::TEXT;
ALTER TABLE login_attempts ALTER COLUMN lockout_until TYPE TEXT USING lockout_until::TEXT;

ALTER TABLE login_histories ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE login_histories ALTER COLUMN account_id TYPE TEXT USING account_id::TEXT;
ALTER TABLE login_histories ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;

ALTER TABLE audit_logs ALTER COLUMN id TYPE TEXT USING id::TEXT;
ALTER TABLE audit_logs ALTER COLUMN actor_id TYPE TEXT USING actor_id::TEXT;
ALTER TABLE audit_logs ALTER COLUMN created_at TYPE TEXT USING created_at::TEXT;
");
        }
    }
}
