#!/usr/bin/env python3
"""GitHubPagesPublisher.py -- Prepare and optionally commit/push Pages site artifacts."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


logger = logging.getLogger(__name__)


class GitHubPagesPublisher:
    """Publish pipeline HTML outputs into a GitHub Pages site directory."""

    def __init__(self, repo_root: str | Path, config: Dict[str, Any]) -> None:
        self.repo_root = Path(repo_root)
        self.enabled = bool(config.get("enabled", True))
        self.site_dir = self.repo_root / str(config.get("site_dir", "docs"))
        self.index_source = str(config.get("index_source", "pipeline_overview.html"))
        self.include_files: List[str] = list(
            config.get(
                "include_files",
                [
                    "pipeline_overview.html",
                    "comparison_report.html",
                    "git_security_deltas_report.html",
                    "llm_explainer_report.html",
                ],
            )
        )
        self.include_dirs: List[str] = list(config.get("include_dirs", ["docs"]))
        self.auto_commit = bool(config.get("auto_commit", False))
        self.auto_push = bool(config.get("auto_push", False))
        self.commit_message = str(
            config.get(
                "commit_message",
                "chore(pages): update security pipeline site artifacts",
            )
        )
        self.branch = str(config.get("branch", "main"))

    def publish(self, output_dir: str | Path) -> Dict[str, Any]:
        """Copy selected outputs to Pages dir and optionally commit/push."""
        started = datetime.now().isoformat()
        if not self.enabled:
            return {
                "status": "skipped",
                "started_at": started,
                "reason": "github_pages.enabled is false",
                "site_dir": str(self.site_dir),
            }

        output_path = Path(output_dir)
        self.site_dir.mkdir(parents=True, exist_ok=True)

        copied_files: List[str] = []
        copied_dirs: List[str] = []
        missing: List[str] = []

        for rel_name in self.include_files:
            src = output_path / rel_name
            dst = self.site_dir / rel_name
            if not src.exists():
                missing.append(rel_name)
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied_files.append(str(dst))

        for rel_name in self.include_dirs:
            src_dir = output_path / rel_name
            dst_dir = self.site_dir / rel_name
            if not src_dir.exists() or not src_dir.is_dir():
                missing.append(rel_name)
                continue
            if dst_dir.exists():
                shutil.rmtree(dst_dir)
            shutil.copytree(src_dir, dst_dir)
            copied_dirs.append(str(dst_dir))

        index_src = output_path / self.index_source
        index_dst = self.site_dir / "index.html"
        if index_src.exists():
            shutil.copy2(index_src, index_dst)
        else:
            self._write_fallback_index(index_dst)
            missing.append(self.index_source)

        (self.site_dir / ".nojekyll").write_text("", encoding="utf-8")

        metadata = {
            "published_at": datetime.now().isoformat(),
            "source_output_dir": str(output_path),
            "site_dir": str(self.site_dir),
            "copied_files": copied_files,
            "copied_dirs": copied_dirs,
            "missing_artifacts": missing,
            "index_source": self.index_source,
        }
        meta_path = self.site_dir / "site_metadata.json"
        meta_path.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        commit_info = self._maybe_commit_and_push()

        result = {
            "status": "ok",
            "started_at": started,
            "site_dir": str(self.site_dir),
            "index_path": str(index_dst),
            "copied_files_count": len(copied_files),
            "copied_dirs_count": len(copied_dirs),
            "missing_artifacts": missing,
            "auto_commit": self.auto_commit,
            "auto_push": self.auto_push,
            **commit_info,
        }
        logger.info(
            "GitHub Pages site prepared at %s (files=%d dirs=%d missing=%d)",
            self.site_dir,
            len(copied_files),
            len(copied_dirs),
            len(missing),
        )
        return result

    def _write_fallback_index(self, path: Path) -> None:
        links = []
        for name in self.include_files:
            links.append(f'<li><a href="{name}">{name}</a></li>')
        links.append('<li><a href="docs/">docs/</a></li>')
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Extractor Pipeline Overview</title>
</head>
<body>
  <h1>Security Extractor Pipeline Overview</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
  <p>Fallback index generated because pipeline_overview.html was missing.</p>
  <ul>
    {''.join(links)}
  </ul>
</body>
</html>
"""
        path.write_text(html, encoding="utf-8")

    def _maybe_commit_and_push(self) -> Dict[str, Any]:
        if not self.auto_commit:
            return {"committed": False, "pushed": False}

        rel_site = self.site_dir.relative_to(self.repo_root)
        self._run_git(["git", "add", str(rel_site)])

        has_changes = self._run_git_quiet(
            ["git", "diff", "--cached", "--quiet", "--", str(rel_site)]
        )
        if has_changes == 0:
            return {"committed": False, "pushed": False}

        self._run_git(["git", "commit", "-m", self.commit_message])
        pushed = False
        if self.auto_push:
            self._run_git(["git", "push", "origin", self.branch])
            pushed = True
        return {"committed": True, "pushed": pushed}

    def _run_git(self, cmd: List[str]) -> None:
        subprocess.run(
            cmd,
            cwd=self.repo_root,
            check=True,
            capture_output=True,
            text=True,
        )

    def _run_git_quiet(self, cmd: List[str]) -> int:
        proc = subprocess.run(
            cmd,
            cwd=self.repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
        return proc.returncode
