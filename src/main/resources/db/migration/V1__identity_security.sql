CREATE TABLE identity_account (
 id uuid PRIMARY KEY,
 login varchar(254) NOT NULL UNIQUE CHECK (login = lower(trim(login))),
 password_hash varchar(512) NOT NULL,
 state varchar(16) NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE','LOCKED','DISABLED')),
 credential_version bigint NOT NULL DEFAULT 0,
 mfa_secret text,
 mfa_pending text,
 mfa_pending_until timestamptz,
 mfa_last_step bigint NOT NULL DEFAULT -1,
 created_at timestamptz NOT NULL
);
CREATE TABLE permission (name varchar(64) PRIMARY KEY);
CREATE TABLE role (name varchar(32) PRIMARY KEY);
CREATE TABLE role_permission (
 role_name varchar(32) REFERENCES role(name), permission_name varchar(64) REFERENCES permission(name),
 PRIMARY KEY(role_name, permission_name)
);
CREATE TABLE identity_role (
 identity_id uuid REFERENCES identity_account(id), role_name varchar(32) REFERENCES role(name),
 PRIMARY KEY(identity_id,role_name)
);
INSERT INTO permission VALUES ('identity:read'),('identity:manage'),('audit:read'),('metrics:read');
INSERT INTO role VALUES ('USER'),('ADMIN');
INSERT INTO role_permission VALUES ('USER','identity:read'),('ADMIN','identity:read'),('ADMIN','identity:manage'),('ADMIN','audit:read'),('ADMIN','metrics:read');
CREATE TABLE security_throttle (
 bucket varchar(128) PRIMARY KEY, attempts integer NOT NULL CHECK (attempts > 0), expires_at timestamptz NOT NULL
);
CREATE TABLE recovery_code (
 identity_id uuid REFERENCES identity_account(id), digest char(64) NOT NULL UNIQUE,
 PRIMARY KEY(identity_id,digest)
);
CREATE TABLE password_reset (
 digest char(64) PRIMARY KEY, identity_id uuid NOT NULL REFERENCES identity_account(id),
 expires_at timestamptz NOT NULL, consumed_at timestamptz
);
CREATE INDEX reset_identity ON password_reset(identity_id);
CREATE TABLE spent_refresh (
 digest char(64) PRIMARY KEY, authorization_id varchar(100) NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE security_audit (
 id uuid PRIMARY KEY, occurred_at timestamptz NOT NULL, actor uuid,
 action varchar(64) NOT NULL, outcome varchar(16) NOT NULL,
 target uuid, correlation_id uuid NOT NULL
);
CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'security_audit is append only'; END $$;
CREATE TRIGGER security_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON security_audit
FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
