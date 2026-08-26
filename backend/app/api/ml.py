from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.models import Endpoint, Finding, FuzzResult, Scan
from app.ml.engine import MLEngine
from app.schemas.ml import (
    MLModelStatusResponse,
    MLPredictionInput,
    MLPredictionResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])


@router.get("/status", response_model=MLModelStatusResponse)
async def get_ml_status():
    """
    Check the operational status of the ML model and preprocessor pipeline.
    """
    engine = MLEngine.get_instance()
    return MLModelStatusResponse(
        status="ready" if engine.is_ready else "offline",
        model_loaded=engine.model is not None,
        preprocessor_loaded=engine.preprocessor is not None,
        model_metadata=engine.metadata,
        raw_feature_names=engine.raw_feature_names,
        processed_feature_names=engine.processed_feature_names
    )


@router.post("/predict", response_model=MLPredictionResponse)
async def predict_vulnerability(input_data: MLPredictionInput):
    """
    Perform vulnerability classification inference using the 19 raw features.
    The preprocessor converts 19 raw features into 27 features for the XGBoost model.
    """
    engine = MLEngine.get_instance()
    if not engine.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Inference Engine is not initialized or model artifacts are missing."
        )

    try:
        features_dict = input_data.model_dump()
        result = engine.predict(features_dict)
        return result
    except ValueError as ve:
        logger.warning(f"ML Validation error: {ve}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.error(f"ML Prediction failure: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference execution failed: {str(e)}"
        )


@router.post("/predict-endpoint/{endpoint_id}", response_model=MLPredictionResponse)
async def predict_endpoint_by_id(endpoint_id: str, db: AsyncSession = Depends(get_db)):
    """
    Construct the 19-feature vector from database records for a specific endpoint and run ML inference.
    """
    engine = MLEngine.get_instance()
    if not engine.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Inference Engine is not initialized."
        )

    # 1. Fetch endpoint
    stmt = select(Endpoint).options(selectinload(Endpoint.parameters)).where(Endpoint.id == endpoint_id)
    res = await db.execute(stmt)
    endpoint = res.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # 2. Fetch latest fuzz result telemetry if available
    fuzz_stmt = (
        select(FuzzResult)
        .where(FuzzResult.endpoint_id == endpoint_id)
        .order_by(FuzzResult.executed_at.desc())
        .limit(1)
    )
    fuzz_res = (await db.execute(fuzz_stmt)).scalar_one_or_none()

    # 3. Determine endpoint type category
    ep_type = "API" if endpoint.is_api else "PAGE"
    path_lower = (endpoint.path or "").lower()
    if "/auth" in path_lower or "/login" in path_lower:
        ep_type = "AUTH"

    # 4. Count query vs body parameters
    query_count = 0
    body_count = 0
    for p in endpoint.parameters or []:
        if (p.location or "").lower() == "query":
            query_count += 1
        elif (p.location or "").lower() == "body":
            body_count += 1

    # 5. Build 19 raw features
    features: Dict[str, Any] = {
        "http_method": (endpoint.method or "GET").upper(),
        "endpoint_depth": int(endpoint.depth or 0),
        "endpoint_type": ep_type,
        "parameter_count": len(endpoint.parameters or []),
        "query_parameter_count": query_count,
        "body_parameter_count": body_count,
        "authentication_required": 1 if endpoint.status_code in [401, 403] else 0,
        "external_exposure": 0,  # 0 for local/internal target
        "response_status": fuzz_res.status_code if fuzz_res else (endpoint.status_code or 200),
        "response_size": len(fuzz_res.details or "") if fuzz_res else 500,
        "response_time": float((fuzz_res.response_time_ms or 50.0) / 1000.0) if fuzz_res else 0.05,
        "response_anomaly_score": 0.85 if (fuzz_res and fuzz_res.anomaly_detected) else 0.0,
        "graph_degree": 2 + len(endpoint.parameters or []),
        "related_endpoint_count": 2,
        "api_relationship_count": 1 if endpoint.is_api else 0,
        "subdomain_relationship": 0,
        "vhost_relationship": 0,
        "previous_vulnerability_evidence": 1 if (fuzz_res and fuzz_res.anomaly_detected) else 0,
        "fuzzing_history": 1 if fuzz_res else 0,
    }

    # Validate against MLPredictionInput
    validated_input = MLPredictionInput(**features)
    return engine.predict(validated_input.model_dump())
