#!/bin/sh
# Creates the restricted role the gateway actually connects as.
#
# Why this file exists: the role named by POSTGRES_USER in the official
# postgres Docker image is the bootstrap role that ran initdb, which Postgres
# requires to be a superuser and will not let you strip that attribute from
# (ALTER ROLE ... NOSUPERUSER fails with "must be owner of ... the bootstrap
# user must have the SUPERUSER attribute"). Superusers unconditionally bypass
# row-level security — ENABLE ROW LEVEL SECURITY and FORCE ROW LEVEL SECURITY
# both say so explicitly in the Postgres documentation, and neither can
# override it. So an application that just connects as POSTGRES_USER gets
# every query answered correctly and every RLS policy in
# internal/store/postgres/migrations/0002_rls.sql silently ignored: nothing
# errors, nothing warns, tenant isolation simply is not there.
#
# The fix is this dedicated, ordinary role. It owns the database and its
# schema (so migrations — including CREATE EXTENSION pgcrypto, a "trusted"
# extension installable by a non-superuser database owner since Postgres 13 —
# run under it and it becomes the owner of every object it creates, which is
# what lets FORCE ROW LEVEL SECURITY actually restrict it). It has neither
# SUPERUSER nor BYPASSRLS. The gateway's own startup check
# (postgres.DB.VerifyRLSEnforceable) refuses to run at all if it is ever
# pointed at a role with either attribute, as a second line of defence against
# this exact misconfiguration creeping back in.
#
# This runs as a shell script (rather than a plain .sql file) specifically so
# the password can come from GATEWAY_APP_PASSWORD in the container's own
# environment instead of being a secret checked into source control. Files in
# docker-entrypoint-initdb.d run once, only against a brand-new data directory,
# as the POSTGRES_USER bootstrap role.

set -eu

: "${GATEWAY_APP_PASSWORD:?GATEWAY_APP_PASSWORD must be set for the postgres container}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
            CREATE ROLE gateway_app LOGIN
                PASSWORD '${GATEWAY_APP_PASSWORD}'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
        END IF;
    END
    \$\$;

    ALTER DATABASE ${POSTGRES_DB} OWNER TO gateway_app;
    ALTER SCHEMA public OWNER TO gateway_app;
    GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB} TO gateway_app;
SQL
