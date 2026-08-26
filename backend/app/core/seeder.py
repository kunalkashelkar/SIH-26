import logging
from sqlalchemy.future import select
from app.core.database import AsyncSessionLocal
from app.models.models import PayloadItem, Project, Target
from app.scanner.fuzzer.payload_manager import PayloadManager

logger = logging.getLogger(__name__)

async def seed_initial_data():
    """Seed initial payload library and baseline structure if empty."""
    async with AsyncSessionLocal() as db:
        try:
            # 1. Seed Payload Items
            res = await db.execute(select(PayloadItem))
            existing_payloads = res.scalars().all()
            if not existing_payloads:
                logger.info("Seeding initial payload library...")
                for category, payload_list in PayloadManager.PAYLOADS.items():
                    for item in payload_list:
                        p_item = PayloadItem(
                            category=category,
                            payload=item["payload"],
                            indicator=item.get("indicator"),
                            description=item.get("desc"),
                            is_custom=False,
                            usage_count=0,
                            success_count=0
                        )
                        db.add(p_item)
                await db.commit()
                logger.info("Payload library seeded successfully.")

            # 2. Seed Default Project & Target if none exist
            proj_res = await db.execute(select(Project))
            if not proj_res.scalars().first():
                default_proj = Project(
                    name="Default Security Workspace",
                    description="Standard production and staging target environment"
                )
                db.add(default_proj)
                await db.commit()
                await db.refresh(default_proj)

                default_target = Target(
                    project_id=default_proj.id,
                    name="Example Web App",
                    base_url="https://example.com",
                    description="Default starting target for security verification"
                )
                db.add(default_target)
                await db.commit()
                logger.info("Default project and target seeded.")
        except Exception as e:
            logger.error(f"Error seeding initial database data: {e}")
            await db.rollback()
