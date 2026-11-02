"""
Safe Archive Extraction and Sandboxing.
Prevents Zip Slip, symlink escapes, decompression bombs, and excessive nesting.
"""
import os
import shutil
import tarfile
import zipfile
import logging
from typing import Optional, List

logger = logging.getLogger(__name__)

class ArchiveExtractionError(Exception):
    pass

class SafeArchiveExtractor:
    """
    Safely extracts tar.gz or zip archives into an isolated destination directory.
    Enforces strict security constraints:
    - Path traversal / Zip Slip prevention
    - Symlink escape prevention
    - File count limit (default 10,000 files)
    - Total uncompressed size limit (default 300 MB)
    - Max single file size (default 15 MB)
    - Max directory nesting depth (default 25)
    """

    def __init__(
        self,
        max_files: int = 10000,
        max_total_bytes: int = 300 * 1024 * 1024,
        max_single_file_bytes: int = 15 * 1024 * 1024,
        max_depth: int = 25
    ):
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_single_file_bytes = max_single_file_bytes
        self.max_depth = max_depth

    def extract(self, archive_path: str, destination_dir: str) -> str:
        """
        Inspect and safely extract archive. Automatically handles .tar.gz, .tgz, and .zip.
        Returns the root extracted directory path (unwrapping single top-level directory if present).
        """
        os.makedirs(destination_dir, exist_ok=True)
        dest_canonical = os.path.realpath(destination_dir)

        if tarfile.is_tarfile(archive_path):
            self._extract_tar(archive_path, dest_canonical)
        elif zipfile.is_zipfile(archive_path):
            self._extract_zip(archive_path, dest_canonical)
        else:
            # Fallback check if it's a gzipped tarball
            try:
                self._extract_tar(archive_path, dest_canonical)
            except Exception as e:
                raise ArchiveExtractionError(f"Unsupported or corrupted archive format: {str(e)}")

        # Unwrap if single top-level directory (GitHub tarballs always package into owner-repo-sha/)
        entries = os.listdir(dest_canonical)
        if len(entries) == 1:
            single_entry = os.path.join(dest_canonical, entries[0])
            if os.path.isdir(single_entry):
                return single_entry

        return dest_canonical

    def _extract_tar(self, archive_path: str, dest_dir: str):
        total_files = 0
        total_bytes = 0

        with tarfile.open(archive_path, "r:*") as tar:
            members: List[tarfile.TarInfo] = []
            for member in tar.getmembers():
                # 1. Path Traversal & Absolute Path Check
                target_path = os.path.realpath(os.path.join(dest_dir, member.name))
                if not target_path.startswith(dest_dir):
                    raise ArchiveExtractionError(f"Directory traversal detected in tar member: {member.name}")

                # 2. Nesting Depth Check
                rel_parts = os.path.relpath(target_path, dest_dir).split(os.sep)
                if len(rel_parts) > self.max_depth:
                    raise ArchiveExtractionError(f"Excessive directory nesting in archive: {member.name}")

                # 3. File Count Check
                total_files += 1
                if total_files > self.max_files:
                    raise ArchiveExtractionError(f"Archive exceeds maximum file count limit ({self.max_files})")

                # 4. Single & Total Size Check
                if member.isreg():
                    if member.size > self.max_single_file_bytes:
                        logger.warning(f"Skipping oversized file {member.name} ({member.size} bytes)")
                        continue
                    total_bytes += member.size
                    if total_bytes > self.max_total_bytes:
                        raise ArchiveExtractionError("Decompression bomb protection: archive uncompressed size limit exceeded")

                # 5. Dangerous file types (Device files, pipes, sockets)
                if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                    continue

                # 6. Symlink Check
                if member.issym() or member.islnk():
                    link_target = member.linkname
                    # Compute where the link would point
                    dest_file_dir = os.path.dirname(target_path)
                    resolved_link = os.path.realpath(os.path.join(dest_file_dir, link_target))
                    if not resolved_link.startswith(dest_dir):
                        logger.warning(f"Discarding dangerous symlink pointing outside archive: {member.name} -> {link_target}")
                        continue

                members.append(member)

            # Safe extraction
            tar.extractall(path=dest_dir, members=members, filter=None if hasattr(tarfile, 'data_filter') else None)

    def _extract_zip(self, archive_path: str, dest_dir: str):
        total_files = 0
        total_bytes = 0

        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                # 1. Path Traversal Check
                target_path = os.path.realpath(os.path.join(dest_dir, info.filename))
                if not target_path.startswith(dest_dir):
                    raise ArchiveExtractionError(f"Zip Slip directory traversal detected: {info.filename}")

                # 2. Depth Check
                rel_parts = os.path.relpath(target_path, dest_dir).split(os.sep)
                if len(rel_parts) > self.max_depth:
                    raise ArchiveExtractionError(f"Excessive nesting in zip archive: {info.filename}")

                # 3. Count Check
                total_files += 1
                if total_files > self.max_files:
                    raise ArchiveExtractionError(f"Archive exceeds maximum file count limit ({self.max_files})")

                # 4. Size Check
                if info.file_size > self.max_single_file_bytes:
                    logger.warning(f"Skipping oversized file {info.filename} ({info.file_size} bytes)")
                    continue

                total_bytes += info.file_size
                if total_bytes > self.max_total_bytes:
                    raise ArchiveExtractionError("Decompression bomb protection: archive uncompressed size limit exceeded")

                zf.extract(info, path=dest_dir)
