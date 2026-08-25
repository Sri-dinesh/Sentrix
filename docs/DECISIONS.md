# Sentrix Architectural Decisions Record (ADR)

## ADR 001: Supabase PostgreSQL Time-Series Strategy & TimescaleDB Fallback

- **Date**: 2026-08-25
- **Status**: Accepted
- **Context**: Task 2.0 of `Sentrix_Implementation_Plan.md` requires verifying native `timescaledb` extension availability on the provisioned Supabase PostgreSQL instance (`unfmcryvabbuncsfyhvu`, PostgreSQL 17.6) before designing the database migrations for the `flows` table.
- **Verification Result**: Executing `CREATE EXTENSION IF NOT EXISTS timescaledb;` against the Supabase instance returned:
  `ERROR: extension "timescaledb" is not available`.
- **Decision**: 
  1. We adopt the documented fallback architecture for time-series flow storage.
  2. The `flows` table will be created as a standard PostgreSQL table with:
     - B-Tree index on `captured_at DESC` for fast time-window range filtering.
     - Single-column indexes on `src_ip` and `dst_ip`.
     - Composite index on `(src_ip, captured_at)` for high-performance forensic searches.
  3. If historical volume exceeds storage/index efficiency in production, native declarative PostgreSQL table partitioning (e.g. `PARTITION BY RANGE (captured_at)`) will be applied.
- **Consequences**: No external dependency on TimescaleDB is required; all SQLAlchemy ORM models, Alembic migrations, and repository queries remain portable and fully compatible with vanilla PostgreSQL 17+.
