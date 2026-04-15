"""Git tools for cloning and inspecting repositories."""

from __future__ import annotations

import os
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Optional
import git

logger = logging.getLogger(__name__)


def clone_repository(repo_url: str, target_dir: Optional[str] = None) -> str:
    """
    Clone a GitHub repository to a local directory.

    Args:
        repo_url: GitHub repository URL (https or git format)
        target_dir: Optional target directory. If None, creates a temp dir.

    Returns:
        Path to the cloned repository.
    """
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="secscanner_")

    logger.info(f"Cloning {repo_url} into {target_dir}")

    try:
        git.Repo.clone_from(
            repo_url,
            target_dir,
            depth=1,  # shallow clone for speed
            progress=_clone_progress,
        )
        logger.info(f"Successfully cloned to {target_dir}")
        return target_dir
    except git.exc.GitCommandError as e:
        logger.error(f"Failed to clone repository: {e}")
        raise RuntimeError(f"Failed to clone {repo_url}: {e}") from e


def _clone_progress(op_code, cur_count, max_count=None, message=""):
    """Log git clone progress."""
    if message:
        logger.debug(f"Git clone progress: {message}")


def cleanup_repository(repo_path: str) -> None:
    """Remove a cloned repository directory."""
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)
        logger.info(f"Cleaned up repository at {repo_path}")


def get_repo_metadata(repo_path: str) -> dict:
    """
    Get basic metadata about a repository.

    Returns:
        Dict with branch, commit hash, remote URL, etc.
    """
    try:
        repo = git.Repo(repo_path)
        metadata = {
            "branch": repo.active_branch.name if not repo.head.is_detached else "HEAD",
            "commit_hash": repo.head.commit.hexsha[:8],
            "commit_message": repo.head.commit.message.strip(),
            "author": str(repo.head.commit.author),
            "committed_date": repo.head.commit.committed_datetime.isoformat(),
        }
        if repo.remotes:
            metadata["remote_url"] = repo.remotes[0].url
        return metadata
    except Exception as e:
        logger.warning(f"Could not get repo metadata: {e}")
        return {}


def list_all_files(repo_path: str, max_files: int = 5000) -> list[str]:
    """
    List all files in the repository, excluding .git directory.

    Returns:
        List of relative file paths.
    """
    repo_root = Path(repo_path)
    files = []

    excluded_dirs = {".git", "node_modules", "__pycache__", ".pytest_cache",
                     "venv", ".venv", "env", "target", "build", "dist",
                     ".gradle", ".mvn", "vendor", "bower_components"}
    excluded_extensions = {
        ".jar", ".war", ".ear", ".zip", ".tar", ".gz", ".png", ".jpg",
        ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
        ".eot", ".mp4", ".mp3", ".avi", ".pdf", ".bin", ".exe", ".so",
        ".dylib", ".dll", ".class", ".pyc", ".pyo",
    }

    for path in repo_root.rglob("*"):
        if path.is_file():
            # Check if any parent directory is in excluded_dirs
            relative = path.relative_to(repo_root)
            parts = relative.parts
            if any(part in excluded_dirs for part in parts):
                continue
            if path.suffix.lower() in excluded_extensions:
                continue
            files.append(str(relative))
            if len(files) >= max_files:
                logger.warning(f"File list truncated at {max_files} files")
                break

    return sorted(files)


def read_file_content(repo_path: str, relative_path: str, max_bytes: int = 500_000) -> Optional[str]:
    """
    Read the content of a file within the repository.

    Returns:
        File content as string, or None if unreadable.
    """
    full_path = Path(repo_path) / relative_path
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
        return content
    except Exception as e:
        logger.debug(f"Could not read {relative_path}: {e}")
        return None


def count_lines_in_repo(repo_path: str, file_list: list[str]) -> int:
    """Count total lines of code across all files."""
    total = 0
    for relative_path in file_list:
        content = read_file_content(repo_path, relative_path)
        if content:
            total += content.count("\n") + 1
    return total
