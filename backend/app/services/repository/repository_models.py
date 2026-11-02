"""
Repository Acquisition and Validation Models.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class RepositoryValidationRequest(BaseModel):
    repository_url: str = Field(..., description="GitHub repository URL (e.g., https://github.com/owner/repo)")
    branch: Optional[str] = Field(None, description="Optional branch or tag name")
    commit_sha: Optional[str] = Field(None, description="Optional commit SHA")
    github_token: Optional[str] = Field(None, description="Optional personal access token for private repositories")

class RepositoryBranchInfo(BaseModel):
    name: str
    commit_sha: str
    protected: bool = False

class RepositoryMetadata(BaseModel):
    valid: bool
    provider: str = "github"
    owner: str
    repository: str
    visibility: str = "public" # "public" or "private"
    default_branch: str = "main"
    selected_branch: str = "main"
    resolved_commit_sha: str
    access_status: str = "accessible" # "accessible", "private_unauthorized", "not_found", "rate_limited"
    message: str = "Repository validated successfully"
    repository_id: Optional[int] = None
    description: Optional[str] = None
    size_kb: Optional[int] = None
    stars_count: Optional[int] = None
    forks_count: Optional[int] = None
    primary_language: Optional[str] = None
    last_updated_at: Optional[str] = None
    available_branches: List[str] = Field(default_factory=list)

class SourceFileEntry(BaseModel):
    rel_path: str
    abs_path: str
    file_name: str
    extension: str
    language: str
    classification: str # "SOURCE", "TEST", "CONFIG", "MANIFEST", "SPECIFICATION", "ASSET", "OTHER"
    size_bytes: int
    lines_count: int
    is_eligible: bool = True
    exclusion_reason: Optional[str] = None

class FileInventorySummary(BaseModel):
    total_files: int = 0
    analyzed_files: int = 0
    skipped_files: int = 0
    total_lines: int = 0
    languages: Dict[str, int] = Field(default_factory=dict) # language -> file count
    classifications: Dict[str, int] = Field(default_factory=dict)
    exclusions: Dict[str, int] = Field(default_factory=dict) # reason -> count
