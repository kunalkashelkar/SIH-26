from pydantic import BaseModel, Field
from typing import Generic, TypeVar, Optional, List, Dict, Any

T = TypeVar("T")

class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class StandardResponse(BaseModel, Generic[T]):
    """Standardized API response envelope."""
    success: bool = True
    data: Optional[T] = None
    error: Optional[ErrorDetail] = None

class PaginationMeta(BaseModel):
    page: int = Field(ge=1, default=1)
    limit: int = Field(ge=1, le=500, default=50)
    total: int = Field(ge=0, default=0)
    total_pages: int = Field(ge=0, default=0)

class PaginatedData(BaseModel, Generic[T]):
    items: List[T] = []
    pagination: PaginationMeta

class PaginatedResponse(BaseModel, Generic[T]):
    success: bool = True
    data: PaginatedData[T]
    error: Optional[ErrorDetail] = None

class MessageResponse(BaseModel):
    message: str
    status: str = "success"
