from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


class MLPredictionInput(BaseModel):
    """
    19 raw features for XGBoost vulnerability detection model.
    """
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = Field(
        ..., description="HTTP Method of the request"
    )
    endpoint_depth: int = Field(
        ..., ge=0, description="URI path depth (0 for root, 1 for /path, etc.)"
    )
    endpoint_type: Literal["API", "AUTH", "FILE", "PAGE", "UNKNOWN"] = Field(
        ..., description="Classification category of the endpoint"
    )
    parameter_count: int = Field(
        ..., ge=0, description="Total parameters observed on the endpoint"
    )
    query_parameter_count: int = Field(
        ..., ge=0, description="Number of query parameters"
    )
    body_parameter_count: int = Field(
        ..., ge=0, description="Number of request body parameters"
    )
    authentication_required: int = Field(
        ..., ge=0, le=1, description="1 if endpoint requires auth / returned 401/403, 0 otherwise"
    )
    external_exposure: int = Field(
        ..., ge=0, le=1, description="1 if domain is public Internet-facing, 0 for local/private"
    )
    response_status: int = Field(
        ..., ge=100, le=599, description="Baseline / probed HTTP response status code"
    )
    response_size: int = Field(
        ..., ge=0, description="HTTP response body size in bytes"
    )
    response_time: float = Field(
        ..., ge=0.0, description="Response time in seconds"
    )
    response_anomaly_score: float = Field(
        ..., ge=0.0, description="Differential response anomaly score"
    )
    graph_degree: int = Field(
        ..., ge=0, description="Node degree in the attack surface graph"
    )
    related_endpoint_count: int = Field(
        ..., ge=0, description="Number of neighboring endpoints sharing the same host/parent"
    )
    api_relationship_count: int = Field(
        ..., ge=0, description="Number of connected API definition relationships"
    )
    subdomain_relationship: int = Field(
        ..., ge=0, le=1, description="1 if endpoint resides on a discovered subdomain, 0 otherwise"
    )
    vhost_relationship: int = Field(
        ..., ge=0, le=1, description="1 if endpoint resides on a virtual host, 0 otherwise"
    )
    previous_vulnerability_evidence: int = Field(
        ..., ge=0, description="Historical confirmed findings on this endpoint"
    )
    fuzzing_history: int = Field(
        ..., ge=0, description="Historical fuzzing probe attempts"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "http_method": "POST",
                "endpoint_depth": 4,
                "endpoint_type": "API",
                "parameter_count": 7,
                "query_parameter_count": 5,
                "body_parameter_count": 4,
                "authentication_required": 1,
                "external_exposure": 0,
                "response_status": 500,
                "response_size": 4914,
                "response_time": 1.937,
                "response_anomaly_score": 0.248,
                "graph_degree": 3,
                "related_endpoint_count": 2,
                "api_relationship_count": 1,
                "subdomain_relationship": 0,
                "vhost_relationship": 0,
                "previous_vulnerability_evidence": 1,
                "fuzzing_history": 0
            }
        }
    )


class MLPredictionResponse(BaseModel):
    """
    Prediction result from XGBoost vulnerability model.
    """
    prediction: int = Field(..., description="0 for Not Vulnerable, 1 for Vulnerable")
    label: str = Field(..., description="'Not Vulnerable' or 'Vulnerable'")
    vulnerable_probability: float = Field(..., description="Probability of vulnerability [0.0, 1.0]")
    not_vulnerable_probability: float = Field(..., description="Probability of clean/not vulnerable [0.0, 1.0]")
    model_name: Optional[str] = "XGBoost Vulnerability Detection Model"
    model_type: Optional[str] = "XGBoost"
    raw_feature_count: int = 19
    processed_feature_count: int = 27


class MLModelStatusResponse(BaseModel):
    """
    Status of the loaded ML artifacts.
    """
    status: str
    model_loaded: bool
    preprocessor_loaded: bool
    model_metadata: Optional[dict] = None
    raw_feature_names: list[str] = []
    processed_feature_names: list[str] = []
