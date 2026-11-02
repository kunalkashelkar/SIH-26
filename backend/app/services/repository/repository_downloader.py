"""
Repository Downloader.
Acquires repository source archives via GitHub REST API streaming tarball downloads or local copies.
"""
import os
import shutil
import tempfile
import logging
from typing import Optional, Dict, Any, Tuple

from app.services.repository.github_client import GitHubClient, GitHubClientError
from app.services.repository.archive_extractor import SafeArchiveExtractor, ArchiveExtractionError
from app.services.repository.repository_models import RepositoryMetadata

logger = logging.getLogger(__name__)

class RepositoryDownloadError(Exception):
    pass

class RepositoryDownloader:
    """
    Downloads repository code without requiring Git on the deployed server.
    """

    def __init__(
        self,
        auth_token: Optional[str] = None,
        max_size_mb: int = 150,
        max_files: int = 10000
    ):
        self.auth_token = auth_token
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.github_client = GitHubClient(auth_token=auth_token)
        self.extractor = SafeArchiveExtractor(
            max_files=max_files,
            max_total_bytes=self.max_size_bytes * 2
        )

    async def acquire_repository(
        self,
        repo_url: str,
        branch: Optional[str] = "main",
        commit_sha: Optional[str] = None
    ) -> Tuple[str, RepositoryMetadata]:
        """
        Download and extract repository.
        Returns:
            extracted_dir (str): Path to the extracted directory containing source code.
            metadata (RepositoryMetadata): Real metadata retrieved from GitHub or local inspection.
        """
        clean_url = repo_url.strip()

        # 1. Local path handling (e.g., ground truth test repo)
        if os.path.isdir(clean_url):
            target_dir = tempfile.mkdtemp(prefix="sentinel_local_repo_")
            self._safe_copy_local_tree(clean_url, target_dir)
            meta = RepositoryMetadata(
                valid=True,
                provider="local",
                owner="local",
                repository=os.path.basename(os.path.normpath(clean_url)),
                visibility="public",
                default_branch=branch or "main",
                selected_branch=branch or "main",
                resolved_commit_sha=commit_sha or "local_test_sha",
                access_status="accessible",
                message="Local repository acquired successfully"
            )
            return target_dir, meta

        # 2. Remote GitHub repository acquisition
        # Validate and resolve commit
        meta = await self.github_client.validate_repository(clean_url, requested_branch=branch, commit_sha=commit_sha)
        if not meta.valid or meta.access_status not in ["accessible", "valid"]:
            raise RepositoryDownloadError(f"Cannot acquire repository: {meta.message}")

        owner = meta.owner
        repo = meta.repository
        ref_to_download = meta.resolved_commit_sha or meta.selected_branch or "HEAD"

        temp_archive_dir = tempfile.mkdtemp(prefix="sentinel_archive_")
        archive_path = os.path.join(temp_archive_dir, f"{repo}-{ref_to_download}.tar.gz")
        extracted_workspace = tempfile.mkdtemp(prefix="sentinel_repo_")

        try:
            logger.info(f"[DOWNLOADER] Streaming archive from GitHub API for {owner}/{repo} (ref: {ref_to_download})...")
            await self.github_client.download_archive(
                owner=owner,
                repo=repo,
                ref=ref_to_download,
                destination_path=archive_path,
                max_size_bytes=self.max_size_bytes
            )

            logger.info(f"[DOWNLOADER] Safely extracting archive to {extracted_workspace}...")
            source_root = self.extractor.extract(archive_path, extracted_workspace)
            return source_root, meta
        except Exception as e:
            # Clean up on failure
            if os.path.exists(extracted_workspace):
                shutil.rmtree(extracted_workspace, ignore_errors=True)
            raise RepositoryDownloadError(f"Failed to acquire repository: {str(e)}")
        finally:
            # Clean up raw downloaded archive
            if os.path.exists(temp_archive_dir):
                shutil.rmtree(temp_archive_dir, ignore_errors=True)

    def _safe_copy_local_tree(self, src: str, dst: str):
        """Safely copy local directory tree avoiding symlink escapes and giant cache directories."""
        src_canonical = os.path.realpath(src)
        for root, dirs, files in os.walk(src):
            # Exclude node_modules, .git, venv
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"]]
            rel_dir = os.path.relpath(root, src)
            target_sub = os.path.join(dst, rel_dir)
            os.makedirs(target_sub, exist_ok=True)

            for f in files:
                sf = os.path.join(root, f)
                df = os.path.join(target_sub, f)
                if os.path.islink(sf):
                    link_target = os.path.realpath(sf)
                    if not link_target.startswith(src_canonical):
                        continue
                try:
                    shutil.copy2(sf, df, follow_symlinks=False)
                except Exception:
                    pass
