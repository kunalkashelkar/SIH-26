import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from app.models.models import Endpoint, Parameter

logger = logging.getLogger(__name__)

class AttackSurfaceAnalyzer:
    def __init__(self, db: AsyncSession, scan_id: str):
        self.db = db
        self.scan_id = scan_id

    async def analyze(self):
        """Analyzes discovered endpoints and calculates priority scores."""
        logger.info(f"Starting Attack Surface analysis for scan {self.scan_id}")
        
        # Fetch all endpoints and their parameters for this scan
        stmt = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        res = await self.db.execute(stmt)
        endpoints = res.scalars().all()
        
        for ep in endpoints:
            score = self.calculate_priority(ep)
            ep.priority_score = score
            self.db.add(ep)
            
        await self.db.commit()

        # Build and analyze NetworkX graph
        from app.scanner.graph.builder import AttackSurfaceGraphBuilder
        from app.scanner.graph.queries import GraphQueries
        
        graph_builder = AttackSurfaceGraphBuilder(self.db, self.scan_id)
        graph = await graph_builder.build()
        coverage = GraphQueries.get_attack_surface_coverage(graph)
        metrics = GraphQueries.calculate_metrics(graph)
        
        logger.info(
            f"Attack Surface Graph built for scan {self.scan_id}: "
            f"Nodes={metrics.get('total_nodes')}, Edges={metrics.get('total_edges')}, "
            f"Coverage={coverage}"
        )
        logger.info(f"Completed Attack Surface analysis for scan {self.scan_id}")

    def calculate_priority(self, endpoint: Endpoint) -> int:
        score = 0
        path_lower = endpoint.path.lower()
        
        # 1. API endpoints are prime targets
        if endpoint.is_api:
            score += 5
        elif "api" in path_lower:
            score += 3
            
        # 2. Authentication and administrative interfaces
        sensitive_keywords = ["login", "admin", "auth", "token", "user", "password", "config", "setup"]
        for kw in sensitive_keywords:
            if kw in path_lower:
                score += 5
                break
                
        # 3. Parameter count (more parameters = more attack surface)
        # 2 points per parameter
        if endpoint.parameters:
            score += len(endpoint.parameters) * 2
            
        return score
