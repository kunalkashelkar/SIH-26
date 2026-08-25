import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from app.core.config import settings

async def test_connection():
    print(f"Connecting to {settings.DATABASE_URL}...")
    engine = create_async_engine(settings.DATABASE_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            row = result.fetchone()
            if row and row[0] == 1:
                print("Database connection successful!")
            else:
                print("Connected but unexpected result.")
    except Exception as e:
        print(f"Database connection failed: {e}")
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(test_connection())
