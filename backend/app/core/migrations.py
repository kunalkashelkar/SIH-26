import logging
from sqlalchemy import text
from app.core.database import engine

logger = logging.getLogger(__name__)

async def run_safe_schema_migrations():
    """
    Safely and idempotently apply additive column migrations across SQLite or PostgreSQL.
    Preserves all existing data and relationships.
    """
    column_migrations = [
        ("targets", "repo_url", "VARCHAR"),
        ("targets", "repo_branch", "VARCHAR DEFAULT 'main'"),
        ("scans", "user_id", "VARCHAR"),
        ("scans", "discovery_mode", "VARCHAR DEFAULT 'WEBSITE_ONLY'"),
        ("scans", "website_url", "VARCHAR"),
        ("scans", "repository_url", "VARCHAR"),
        ("scans", "repository_branch", "VARCHAR DEFAULT 'main'"),
        ("scans", "repository_commit_sha", "VARCHAR"),
        ("scans", "configuration", "JSON"),
        ("findings", "asset_id", "VARCHAR"),
        ("findings", "title", "VARCHAR"),
        ("findings", "technical_details", "TEXT"),
        ("findings", "affected_url", "VARCHAR"),
        ("findings", "affected_endpoint", "VARCHAR"),
        ("findings", "http_method", "VARCHAR"),
        ("findings", "parameter_name", "VARCHAR"),
        ("findings", "source_file", "VARCHAR"),
        ("findings", "source_line_start", "INTEGER"),
        ("findings", "source_line_end", "INTEGER"),
        ("findings", "detection_method", "VARCHAR"),
        ("findings", "validation_method", "VARCHAR"),
        ("findings", "first_detected_at", "DATETIME"),
        ("findings", "last_updated_at", "DATETIME"),
    ]

    async with engine.begin() as conn:
        for table, col, col_type in column_migrations:
            try:
                # Works on SQLite and PostgreSQL
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type};"))
                logger.info(f"Successfully migrated schema: added column {table}.{col}")
            except Exception as e:
                # Column already exists
                err_str = str(e).lower()
                if "duplicate column" in err_str or "already exists" in err_str or "no such column" not in err_str:
                    logger.debug(f"Column {table}.{col} already exists; skipping.")
                else:
                    logger.warning(f"Notice on column migration {table}.{col}: {e}")
