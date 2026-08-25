import asyncio
import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from app.core.database import Base, engine
from app.models.models import *

async def init():
    print("Creating tables in SQLite...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Done.")

if __name__ == "__main__":
    asyncio.run(init())
