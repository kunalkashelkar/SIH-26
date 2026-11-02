import os
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    from celery import Celery
    celery_app = Celery(
        "cypher_scanner",
        broker=settings.CELERY_BROKER_URL,
        backend=settings.REDIS_URL,
        include=["app.workers.tasks"]
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=3600,       # 1 hour maximum per scan job
        task_soft_time_limit=3300,  # Graceful teardown signal at 55 minutes
        worker_prefetch_multiplier=1,
        task_acks_late=True,        # Guarantee delivery: only acknowledge after task finishes
        broker_connection_retry_on_startup=True
    )
except ImportError:
    Celery = None
    celery_app = None
