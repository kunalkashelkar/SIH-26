"""
Repository Validator.
Validates repository URL format, permissions, accessibility, and resolves branches.
"""
import os
import logging
from typing import Optional

from app.services.repository.repository_models import RepositoryMetadata, RepositoryValidationRequest
from app.services.repository.github_client import GitHubClient, GitHubClientError

logger = logging.getLogger(__name__)

class RepositoryValidator:
    """
    Validates GitHub repositories and local test repositories against security and accessibility rules.
    """

    def __init__(self, auth_token: Optional[str] = None):
        self.auth_token = auth_token
        self.github_client = GitHubClient(auth_token=auth_token)

    async def validate(self, request: RepositoryValidationRequest) -> RepositoryMetadata:
        url = request.repository_url.strip()

        # 1. Local filesystem path support (for automated test suites and mock targets)
        if os.path.isdir(url):
            repo_name = os.path.basename(os.path.normpath(url))
            return RepositoryMetadata(
                valid=True,
                provider="local",
                owner="local",
                repository=repo_name,
                visibility="public",
                default_branch=request.branch or "main",
                selected_branch=request.branch or "main",
                resolved_commit_sha=request.commit_sha or "0000000000000000000000000000000000000000",
                access_status="accessible",
                message="Local repository validated successfully",
                size_kb=0,
                available_branches=[request.branch or "main"]
            )

        # 2. Remote GitHub validation
        try:
            metadata = await self.github_client.validate_repository(
                repo_url=url,
                requested_branch=request.branch,
                commit_sha=request.commit_sha
            )
            return metadata
        except GitHubClientError as e:
            owner = "unknown"
            repo = "unknown"
            try:
                owner, repo, _ = GitHubClient.parse_github_url(url)
            except Exception:
                pass

            return RepositoryMetadata(
                valid=False,
                provider="github",
                owner=owner,
                repository=repo,
                visibility="unknown",
                default_branch="main",
                selected_branch=request.branch or "main",
                resolved_commit_sha="",
                access_status=e.access_status,
                message=e.message,
                available_branches=[]
            )
