"""
SecurityDeltaExtractor.py - Class-based Offline Git Repository Security Analysis
====================================================================
"""

import difflib
import json
import logging
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field

import git
from git import Repo

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    keywords: list = field(default_factory=list)
    iac_extensions: set = field(default_factory=set)
    iac_filenames: set = field(default_factory=set)
    iac_paths: list = field(default_factory=list)
    exclude_patterns: list = field(default_factory=list)

    @classmethod
    def from_yaml(cls, config_path: str = "security_config.yaml") -> "SecurityConfig":
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config %s not found. Using defaults.", config_path)
            return cls()
        with open(path, "r") as f:
            raw = yaml.safe_load(f) or {}
        return cls(
            keywords=raw.get("keywords", []),
            iac_extensions=set(raw.get("iac_extensions", [])),
            iac_filenames=set(raw.get("iac_filenames", [])),
            iac_paths=raw.get("iac_paths", []),
            exclude_patterns=raw.get("exclude_patterns", []),
        )


class SecurityDeltaExtractor:
    """Scans a local Git repository for security-related IaC changes."""

    def __init__(self, repo_path: str, config: SecurityConfig):
        self.repo_path = Path(repo_path)
        self.config = config
        self.repo = self._open_repo()

    def _open_repo(self) -> Repo:
        if not self.repo_path.exists():
            raise FileNotFoundError(
                f"Repository not found: {self.repo_path}\n"
                f"Clone it first: git clone <url> {self.repo_path}"
            )
        if not (self.repo_path / ".git").exists():
            raise FileNotFoundError(f"Not a git repository: {self.repo_path}")
        return Repo(self.repo_path)

    def is_iac_file(self, filepath: str) -> bool:
        """Check if file is an Infrastructure-as-Code file by name or extension."""
        path = Path(filepath)
        return (
            path.name in self.config.iac_filenames
            or path.suffix.lower() in self.config.iac_extensions
        )

    def is_iac_path(self, filepath: str) -> bool:
        """Check if file lives in an IaC-related directory."""
        filepath_lower = filepath.lower()
        return any(p in filepath_lower for p in self.config.iac_paths)

    def is_security_related(self, message: str) -> Tuple[bool, List[str]]:
        """Return (True, matched_keywords) if the commit message is security-related."""
        msg_lower = message.lower()
        if any(exc in msg_lower for exc in self.config.exclude_patterns):
            return False, []
        matched = [kw for kw in self.config.keywords if kw.lower() in msg_lower]
        return (len(matched) > 0, matched)

    @staticmethod
    def get_file_content(commit, filepath: str) -> Optional[str]:
        """Get file content at a specific commit."""
        try:
            blob = commit.tree / filepath
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except (KeyError, AttributeError, TypeError):
            return None

    @staticmethod
    def generate_diff(before: str, after: str, filepath: str) -> str:
        """Generate unified diff between two file versions."""
        if not before or not after:
            return ""
        return "\n".join(
            difflib.unified_diff(
                before.splitlines(),
                after.splitlines(),
                fromfile=f"a/{filepath}",
                tofile=f"b/{filepath}",
                lineterm="",
            )
        )

    def run(
        self,
        limit: int = 100,
        branch: str = "main",
        since: str = None,
        iac_only: bool = True,
        iac_paths_only: bool = False,
        verbose: bool = True,
    ) -> List[Dict]:
        """
        Extract security deltas from the repository.

        Parameters
        ----------
        limit : int
            Maximum number of security-related commits to collect.
        branch : str
            Git branch to walk.
        since : str | None
            ISO-format date string; commits before this date are skipped.
        iac_only : bool
            If True, only include files recognised as IaC by name/extension.
        iac_paths_only : bool
            If True, only include files under IaC-related directories.
        verbose : bool
            Print progress and summary information.
        """
        commits_iter = self._resolve_commits(branch, limit, verbose)
        since_date = self._parse_since(since)

        if verbose:
            self._print_header(branch, limit, since)

        dataset: List[Dict] = []
        commits_scanned = 0
        security_commits_found = 0

        for commit in commits_iter:
            commits_scanned += 1

            if verbose and commits_scanned % 500 == 0:
                logger.info(
                    "Scanned %d commits, found %d security-related.",
                    commits_scanned,
                    security_commits_found,
                )

            if since_date:
                commit_date = datetime.fromtimestamp(commit.committed_date)
                if commit_date < since_date:
                    continue

            is_security, matched_keywords = self.is_security_related(commit.message)
            if not is_security:
                continue

            security_commits_found += 1

            if verbose:
                short_msg = commit.message.split("\n")[0][:50]
                logger.info(
                    "[%d] %s: %s...",
                    security_commits_found,
                    commit.hexsha[:7],
                    short_msg,
                )

            if not commit.parents:
                continue

            parent = commit.parents[0]

            try:
                diffs = parent.diff(commit)
            except Exception:
                continue

            for diff_item in diffs:
                filepath = diff_item.b_path or diff_item.a_path
                if not filepath:
                    continue

                if iac_only and not self.is_iac_file(filepath):
                    continue
                if iac_paths_only and not self.is_iac_path(filepath):
                    continue

                before_content = self.get_file_content(parent, filepath)
                after_content = self.get_file_content(commit, filepath)

                if not before_content and not after_content:
                    continue

                diff_text = self.generate_diff(
                    before_content or "", after_content or "", filepath
                )

                entry = {
                    "commit_sha": commit.hexsha,
                    "commit_message": commit.message.strip(),
                    "commit_date": datetime.fromtimestamp(
                        commit.committed_date
                    ).isoformat(),
                    "author": commit.author.name,
                    "file": filepath,
                    "before": before_content or "",
                    "after": after_content or "",
                    "diff": diff_text,
                    "keywords_matched": matched_keywords,
                }
                dataset.append(entry)

            if security_commits_found >= limit:
                if verbose:
                    logger.info("Reached limit of %d security commits", limit)
                break

        if verbose:
            self._print_summary(commits_scanned, security_commits_found, len(dataset))

        return dataset

    def _resolve_commits(self, branch: str, limit: int, verbose: bool):
        """Try branch → master → HEAD, matching the original 3-level fallback."""
        max_count = limit * 20
        try:
            return self.repo.iter_commits(branch, max_count=max_count)
        except git.exc.GitCommandError:
            pass
        try:
            if verbose:
                logger.info("Branch '%s' not found, using 'master'", branch)
            return self.repo.iter_commits("master", max_count=max_count)
        except git.exc.GitCommandError:
            pass
        if verbose:
            logger.info("Using HEAD")
        return self.repo.iter_commits("HEAD", max_count=max_count)

    @staticmethod
    def _parse_since(since: Optional[str]) -> Optional[datetime]:
        if not since:
            return None
        try:
            return datetime.fromisoformat(since)
        except ValueError:
            logger.warning("Invalid date format: %s, ignoring", since)
            return None

    def _print_header(self, branch: str, limit: int, since: Optional[str]):
        logger.info("%s", "=" * 60)
        logger.info("OFFLINE SECURITY DELTA EXTRACTION")
        logger.info("%s", "=" * 60)
        logger.info("Repository: %s", self.repo_path)
        logger.info("Branch: %s", branch)
        logger.info("Keywords: %d configured", len(self.config.keywords))
        logger.info("Limit: %d commits", limit)
        if since:
            logger.info("Since: %s", since)
        logger.info("%s", "=" * 60)

    @staticmethod
    def _print_summary(scanned: int, security: int, deltas: int):
        logger.info("%s", "=" * 60)
        logger.info("EXTRACTION COMPLETE")
        logger.info("%s", "=" * 60)
        logger.info("Commits scanned: %s", f"{scanned:,}")
        logger.info("Security commits: %s", f"{security:,}")
        logger.info("Deltas extracted: %s", f"{deltas:,}")
        logger.info("%s", "=" * 60)


    @staticmethod
    def save_jsonl(data: List[Dict], filepath: str):
        """Save data to JSONL format with safe serialisation for datetime, etc."""
        with open(filepath, "w", encoding="utf-8") as f:
            for entry in data:
                f.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
        logger.info("Saved %d entries to %s", len(data), filepath)
