import asyncio
import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from models.models import Base
from core.database import engine

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

if __name__ == "__main__":
    asyncio.run(init_db())
    print("Database initialized.")
