import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.database import get_db
from app.models.models import Scan
from app.schemas.graph import GraphResponse
from app.scanner.graph.builder import AttackSurfaceGraphBuilder
from app.scanner.graph.serializer import GraphSerializer

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/{scan_id}/graph", response_model=GraphResponse)
async def get_scan_graph(scan_id: str, db: AsyncSession = Depends(get_db)):
    """
    Returns the complete attack surface graph built using NetworkX for the requested scan.
    """
    # Verify scan exists
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    builder = AttackSurfaceGraphBuilder(db, scan_id)
    graph = await builder.build()
    
    serialized_graph = GraphSerializer.serialize(graph)
    return serialized_graph
