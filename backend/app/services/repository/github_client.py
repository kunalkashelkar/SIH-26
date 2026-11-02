"""
GitHub API client for repository metadata, branch resolution, and archive downloads.
"""
import logging
import re
import urllib.parse
from typing import Optional, Dict, Any, List, Tuple
import httpx

from app.services.repository.repository_models import RepositoryMetadata, RepositoryBranchInfo

logger = logging.getLogger(__name__)

GITHUB_URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+?)(?:\.git)?(?:/(?:tree|blob)/([^/\s]+.*))?/?$",
    re.IGNORECASE
)

class GitHubClientError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, access_status: str = "error"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.access_status = access_status

class GitHubClient:
    """
    Robust GitHub API client with timeouts, streaming download, and token authorization.
    """
    BASE_API = "https://api.github.com"

    def __init__(
        self,
        auth_token: Optional[str] = None,
        timeout_seconds: float = 20.0,
        max_redirects: int = 5
    ):
        self.auth_token = auth_token.strip() if auth_token and auth_token.strip() else None
        self.timeout = httpx.Timeout(timeout_seconds, connect=10.0, read=timeout_seconds)
        self.max_redirects = max_redirects

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Sentinel-Web-Security-Scanner/1.0",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    @staticmethod
    def parse_github_url(url: str) -> Tuple[str, str, Optional[str]]:
        """
        Extract (owner, repo, branch_from_url) from various GitHub URL formats:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - https://github.com/owner/repo/tree/feature-branch
        - git@github.com:owner/repo.git
        """
        clean_url = url.strip()
        if clean_url.startswith("git@github.com:"):
            # SSH format: git@github.com:owner/repo.git
            ssh_path = clean_url[len("git@github.com:"):]
            parts = ssh_path.rstrip("/").replace(".git", "").split("/")
            if len(parts) >= 2:
                return parts[0], parts[1], None
            raise GitHubClientError(f"Malformed SSH GitHub URL: {url}", access_status="invalid_url")

        match = GITHUB_URL_PATTERN.match(clean_url)
        if not match:
            raise GitHubClientError(
                f"Invalid GitHub repository URL: '{url}'. Expected format: https://github.com/owner/repo",
                access_status="invalid_url"
            )

        owner = match.group(1)
        repo = match.group(2)
        embedded_branch = match.group(3)

        if owner.startswith("-") or repo.startswith("-"):
            raise GitHubClientError("Suspicious repository name starting with hyphen.", access_status="invalid_url")

        return owner, repo, embedded_branch

    async def validate_repository(
        self,
        repo_url: str,
        requested_branch: Optional[str] = None,
        commit_sha: Optional[str] = None
    ) -> RepositoryMetadata:
        """
        Query GitHub REST API to validate repository access, metadata, branches, and resolved commit SHA.
        """
        owner, repo, embedded_branch = self.parse_github_url(repo_url)
        branch_to_check = requested_branch or embedded_branch

        headers = self._get_headers()

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            repo_api_url = f"{self.BASE_API}/repos/{owner}/{repo}"
            try:
                resp = await client.get(repo_api_url, headers=headers)
            except httpx.TimeoutException:
                raise GitHubClientError("GitHub API request timed out.", access_status="timeout")
            except httpx.RequestError as e:
                raise GitHubClientError(f"Network error contacting GitHub API: {str(e)}", access_status="network_error")

            # Handle access control & error statuses
            if resp.status_code == 404:
                if not self.auth_token:
                    raise GitHubClientError(
                        f"Repository '{owner}/{repo}' not found or is private. If it is private, provide an authorization token.",
                        status_code=404,
                        access_status="not_found_or_private"
                    )
                raise GitHubClientError(f"Repository '{owner}/{repo}' not found on GitHub.", status_code=404, access_status="not_found")
            elif resp.status_code in [401, 403]:
                rate_limit_remaining = resp.headers.get("x-ratelimit-remaining")
                if rate_limit_remaining == "0":
                    reset_time = resp.headers.get("x-ratelimit-reset", "soon")
                    raise GitHubClientError(f"GitHub API rate limit exceeded (resets at {reset_time}).", status_code=403, access_status="rate_limited")
                raise GitHubClientError("GitHub authentication failed or insufficient repository permissions.", status_code=resp.status_code, access_status="private_unauthorized")
            elif resp.status_code != 200:
                raise GitHubClientError(f"GitHub API returned unexpected status {resp.status_code}.", status_code=resp.status_code, access_status="api_error")

            data = resp.json()
            default_branch = data.get("default_branch", "main")
            target_branch = branch_to_check or default_branch

            # 2. Fetch Branches (up to 30)
            available_branches = [default_branch]
            try:
                branches_resp = await client.get(f"{self.BASE_API}/repos/{owner}/{repo}/branches?per_page=30", headers=headers)
                if branches_resp.status_code == 200:
                    b_data = branches_resp.json()
                    available_branches = [b["name"] for b in b_data if "name" in b]
                    if default_branch not in available_branches:
                        available_branches.insert(0, default_branch)
            except Exception as e:
                logger.debug(f"Could not fetch branches list: {e}")

            # 3. Resolve Commit SHA
            resolved_sha = commit_sha
            if not resolved_sha:
                ref_to_resolve = target_branch
                try:
                    commit_resp = await client.get(f"{self.BASE_API}/repos/{owner}/{repo}/commits/{ref_to_resolve}", headers=headers)
                    if commit_resp.status_code == 200:
                        resolved_sha = commit_resp.json().get("sha", "")
                    elif commit_resp.status_code == 404:
                        # Try falling back to default branch if requested branch doesn't exist
                        if target_branch != default_branch:
                            fb_resp = await client.get(f"{self.BASE_API}/repos/{owner}/{repo}/commits/{default_branch}", headers=headers)
                            if fb_resp.status_code == 200:
                                resolved_sha = fb_resp.json().get("sha", "")
                                target_branch = default_branch
                except Exception as e:
                    logger.debug(f"Could not resolve commit SHA: {e}")

            if not resolved_sha:
                resolved_sha = "HEAD"

            return RepositoryMetadata(
                valid=True,
                provider="github",
                owner=data.get("owner", {}).get("login", owner),
                repository=data.get("name", repo),
                visibility="private" if data.get("private", False) else "public",
                default_branch=default_branch,
                selected_branch=target_branch,
                resolved_commit_sha=resolved_sha,
                access_status="accessible",
                message="Repository validated successfully",
                repository_id=data.get("id"),
                description=data.get("description"),
                size_kb=data.get("size", 0),
                stars_count=data.get("stargazers_count", 0),
                forks_count=data.get("forks_count", 0),
                primary_language=data.get("language"),
                last_updated_at=data.get("updated_at"),
                available_branches=available_branches
            )

    async def download_archive(
        self,
        owner: str,
        repo: str,
        ref: str,
        destination_path: str,
        max_size_bytes: int = 150 * 1024 * 1024
    ) -> str:
        """
        Download repository tarball archive from GitHub API and write to destination file.
        Enforces maximum download size limit and stream processing.
        """
        headers = self._get_headers()
        tarball_url = f"{self.BASE_API}/repos/{owner}/{repo}/tarball/{urllib.parse.quote(ref)}"

        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0, read=60.0), follow_redirects=True) as client:
            try:
                async with client.stream("GET", tarball_url, headers=headers) as response:
                    if response.status_code == 404:
                        raise GitHubClientError(f"Repository archive not found for ref '{ref}'.", status_code=404)
                    elif response.status_code in [401, 403]:
                        raise GitHubClientError("Unauthorized to download repository archive.", status_code=response.status_code)
                    elif response.status_code != 200:
                        raise GitHubClientError(f"GitHub archive download returned HTTP {response.status_code}.", status_code=response.status_code)

                    total_downloaded = 0
                    with open(destination_path, "wb") as f:
                        async for chunk in response.aiter_bytes(chunk_size=65536):
                            total_downloaded += len(chunk)
                            if total_downloaded > max_size_bytes:
                                raise GitHubClientError(
                                    f"Repository archive exceeds maximum download limit ({max_size_bytes // (1024*1024)} MB).",
                                    access_status="size_exceeded"
                                )
                            f.write(chunk)

                    return destination_path
            except httpx.TimeoutException:
                raise GitHubClientError("Repository archive download timed out.", access_status="timeout")
            except httpx.RequestError as e:
                raise GitHubClientError(f"Network error during archive download: {str(e)}", access_status="network_error")
