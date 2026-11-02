import os
import asyncio
import pytest

# Ensure all tests run against an isolated test database, preserving the primary development database
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test_sentinel.db"
os.environ["ENVIRONMENT"] = "testing"

from app.core.database import engine, Base
from app.core.migrations import run_safe_schema_migrations

@pytest.fixture(scope="session", autouse=True)
def initialize_test_database():
    """Create all tables and safe indexes in the isolated test database."""
    async def _init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await run_safe_schema_migrations()

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(asyncio.run, _init()).result()
    else:
        loop.run_until_complete(_init())
