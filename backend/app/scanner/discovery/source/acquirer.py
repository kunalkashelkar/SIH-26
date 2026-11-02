"""
Repository Acquisition and Sandboxing.
Safely checks out or extracts source repositories with strict size,
file count, symlink, and path traversal restrictions.
"""
import asyncio
import logging
import os
import re
import shutil
import tempfile
import urllib.parse
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

GITHUB_REPO_REGEX = re.compile(r"^https://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)((/|\.git)?)$")

class SecurityViolationError(Exception):
    """Raised when repository violates security constraints (symlink escape, size limit, path traversal)."""
    pass

class RepositoryAcquisitionError(Exception):
    """Raised when repository cannot be cloned or fetched."""
    pass

class RepositoryAcquirer:
    """
    Safely acquires source code into an isolated temporary workspace.
    Enforces security boundaries:
    - No script execution
    - Max size limits (default 150MB)
    - Max file counts (default 5000 files)
    - Symlink escape prevention
    - Path traversal prevention
    """

    def __init__(
        self,
        repo_url: str,
        branch: Optional[str] = "main",
        commit_sha: Optional[str] = None,
        auth_token: Optional[str] = None,
        max_size_mb: int = 150,
        max_files: int = 5000,
        max_file_size_mb: int = 5
    ):
        self.raw_repo_url = repo_url.strip()
        self.branch = branch or "main"
        self.commit_sha = commit_sha
        self.auth_token = auth_token
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_files = max_files
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        
        self.working_dir: Optional[str] = None
        self.is_local = os.path.exists(self.raw_repo_url)

    def validate_url(self):
        """Validate URL format and prevent argument injection."""
        if self.is_local:
            return
        match = GITHUB_REPO_REGEX.match(self.raw_repo_url)
        if not match:
            raise RepositoryAcquisitionError(f"Invalid GitHub repository URL: {self.raw_repo_url}")
        
        owner, repo = match.group(1), match.group(2)
        if owner.startswith("-") or repo.startswith("-"):
            raise RepositoryAcquisitionError("Suspicious repository name starting with hyphen.")

    async def acquire(self) -> str:
        """Clone or copy repository into a sandboxed temporary directory."""
        self.validate_url()
        self.working_dir = tempfile.mkdtemp(prefix="cypher_repo_")

        try:
            if self.is_local:
                logger.info(f"[ACQUIRE] Copying local test repository from: {self.raw_repo_url}")
                # Copy local files with symlink safety
                self._safe_copy_tree(self.raw_repo_url, self.working_dir)
            else:
                clone_url = self.raw_repo_url
                if self.auth_token:
                    parsed = urllib.parse.urlparse(self.raw_repo_url)
                    clone_url = f"{parsed.scheme}://x-access-token:{self.auth_token}@{parsed.netloc}{parsed.path}"

                cmd = ["git", "clone", "--depth", "1"]
                if self.branch:
                    cmd.extend(["--branch", self.branch])
                cmd.extend([clone_url, self.working_dir])

                logger.info(f"[ACQUIRE] Performing shallow clone of {self.raw_repo_url} (branch: {self.branch})")
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    err_msg = stderr.decode(errors="replace")
                    # Redact auth token if present
                    if self.auth_token:
                        err_msg = err_msg.replace(self.auth_token, "[REDACTED]")
                    raise RepositoryAcquisitionError(f"git clone failed (code {proc.returncode}): {err_msg}")

                # If specific commit requested
                if self.commit_sha:
                    checkout_proc = await asyncio.create_subprocess_exec(
                        "git", "checkout", self.commit_sha,
                        cwd=self.working_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await checkout_proc.communicate()

            # Audit acquired files for size, file count, and symlinks
            self._audit_sandbox(self.working_dir)
            return self.working_dir

        except Exception:
            self.cleanup()
            raise

    def _safe_copy_tree(self, src: str, dst: str):
        """Safely copy directory tree omitting symlinks that point outside."""
        for root, dirs, files in os.walk(src):
            rel_path = os.path.relpath(root, src)
            target_dir = os.path.join(dst, rel_path)
            os.makedirs(target_dir, exist_ok=True)

            for f in files:
                src_file = os.path.join(root, f)
                dst_file = os.path.join(target_dir, f)
                if os.path.islink(src_file):
                    target = os.path.realpath(src_file)
                    if not target.startswith(os.path.realpath(src)):
                        logger.warning(f"Skipping symlink pointing outside repository: {src_file}")
                        continue
                try:
                    shutil.copy2(src_file, dst_file, follow_symlinks=False)
                except Exception as e:
                    logger.debug(f"Could not copy {src_file}: {e}")

    def _audit_sandbox(self, directory: str):
        """Verify directory conforms to file count, file size, and symlink security rules."""
        total_files = 0
        total_size = 0
        canonical_root = os.path.realpath(directory)

        for root, dirs, files in os.walk(directory):
            # Check path traversal
            if not os.path.realpath(root).startswith(canonical_root):
                raise SecurityViolationError(f"Path traversal detected in repository hierarchy: {root}")

            for f in files:
                file_path = os.path.join(root, f)
                total_files += 1

                if total_files > self.max_files:
                    raise SecurityViolationError(f"Repository exceeds maximum file count limit ({self.max_files} files)")

                # Check symlink target
                if os.path.islink(file_path):
                    real_target = os.path.realpath(file_path)
                    if not real_target.startswith(canonical_root):
                        logger.warning(f"Removing dangerous symlink pointing outside sandbox: {file_path}")
                        try:
                            os.remove(file_path)
                        except OSError:
                            pass
                        continue

                try:
                    size = os.path.getsize(file_path)
                    total_size += size
                    if total_size > self.max_size_bytes:
                        raise SecurityViolationError(f"Repository exceeds maximum size limit ({self.max_size_bytes // (1024*1024)} MB)")
                except OSError:
                    pass

    def cleanup(self):
        """Remove the temporary repository directory."""
        if self.working_dir and os.path.exists(self.working_dir):
            try:
                shutil.rmtree(self.working_dir, ignore_errors=True)
                logger.info(f"[ACQUIRE] Sandboxed workspace cleaned up: {self.working_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove sandboxed workspace: {e}")
            self.working_dir = None

    async def __aenter__(self):
        return await self.acquire()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
