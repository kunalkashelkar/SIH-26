"""
Repositories API Router.
Provides repository validation, branch resolution, and metadata inspection.
"""
import logging
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional

from app.services.repository.repository_models import RepositoryValidationRequest, RepositoryMetadata
from app.services.repository.repository_validator import RepositoryValidator
from app.core.security import get_optional_user

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/validate", response_model=RepositoryMetadata)
async def validate_repository(
    request: RepositoryValidationRequest,
    user: Optional[dict] = Depends(get_optional_user)
):
    """
    Validate a GitHub repository URL, retrieve branches, verify access permissions,
    and resolve the target commit SHA from the live GitHub REST API.
    """
    try:
        validator = RepositoryValidator(auth_token=request.github_token)
        metadata = await validator.validate(request)
        if not metadata.valid:
            # Still return 200 with valid: false and access_status so the frontend UI can show clear validation messages
            return metadata
        return metadata
    except Exception as e:
        logger.error(f"Error validating repository: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to validate repository: {str(e)}")
