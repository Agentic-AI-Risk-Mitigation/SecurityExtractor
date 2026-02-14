#!/usr/bin/env python3
"""GitHubPagesPublisher.py -- Prepare and optionally commit/push Pages site artifacts."""

from __future__ import annotations

import html
import json
import logging
import re
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
        self.viewer_max_lines = int(config.get("viewer_max_lines", 1000))

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
        reused_existing_index_source = False

        for rel_name in self.include_files:
            src = output_path / rel_name
            dst = self.site_dir / rel_name
            if not src.exists():
                # Keep an already-published index source file when the run
                # did not regenerate it in output/.
                if rel_name == self.index_source and dst.exists():
                    reused_existing_index_source = True
                    continue
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
        existing_index_src = self.site_dir / self.index_source
        index_dst = self.site_dir / "index.html"
        if index_src.exists():
            shutil.copy2(index_src, index_dst)
        elif existing_index_src.exists():
            shutil.copy2(existing_index_src, index_dst)
            reused_existing_index_source = True
        else:
            self._write_fallback_index(index_dst)
            if self.index_source not in missing:
                missing.append(self.index_source)

        viewer_cfg_result = self._apply_viewer_configuration(output_path)

        (self.site_dir / ".nojekyll").write_text("", encoding="utf-8")

        metadata = {
            "published_at": datetime.now().isoformat(),
            "source_output_dir": str(output_path),
            "site_dir": str(self.site_dir),
            "copied_files": copied_files,
            "copied_dirs": copied_dirs,
            "missing_artifacts": missing,
            "index_source": self.index_source,
            "reused_existing_index_source": reused_existing_index_source,
            **viewer_cfg_result,
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
            "reused_existing_index_source": reused_existing_index_source,
            **viewer_cfg_result,
            **commit_info,
        }
        logger.info(
            "GitHub Pages site prepared at %s (files=%d dirs=%d missing=%d viewer_max_lines=%d viewer_updates=%d)",
            self.site_dir,
            len(copied_files),
            len(copied_dirs),
            len(missing),
            self.viewer_max_lines,
            viewer_cfg_result.get("updated_files", 0),
        )
        return result

    def _apply_viewer_configuration(self, output_path: Path) -> Dict[str, Any]:
        """Apply configured line-limit behavior to pipeline overview/viewer pages."""
        if self.viewer_max_lines <= 0:
            return {"viewer_max_lines": self.viewer_max_lines, "updated_files": 0}

        updated_files = 0

        for overview in (
            self.site_dir / "pipeline_overview.html",
            self.site_dir / "index.html",
        ):
            if overview.exists() and self._rewrite_overview_limit_text(overview):
                updated_files += 1

        viewer_dir = self.site_dir / "docs"
        if viewer_dir.exists() and viewer_dir.is_dir():
            for viewer_file in sorted(viewer_dir.glob("*.html")):
                source_name = viewer_file.name[:-5]  # strip ".html"
                source_path = self._resolve_viewer_source(source_name, output_path)
                if not source_path:
                    continue
                if self._rewrite_viewer_file(viewer_file, source_path):
                    updated_files += 1

        return {"viewer_max_lines": self.viewer_max_lines, "updated_files": updated_files}

    def _rewrite_overview_limit_text(self, html_path: Path) -> bool:
        text = html_path.read_text(encoding="utf-8", errors="replace")
        replaced = re.sub(
            r"truncated to \d+ lines",
            f"truncated to {self.viewer_max_lines} lines",
            text,
        )
        if replaced == text:
            return False
        html_path.write_text(replaced, encoding="utf-8")
        return True

    def _resolve_viewer_source(
        self,
        source_name: str,
        output_path: Path,
    ) -> Path | None:
        candidates = [
            output_path / source_name,
            self.repo_root / "config" / source_name,
            self.repo_root / source_name,
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def _rewrite_viewer_file(self, viewer_file: Path, source_file: Path) -> bool:
        source_lines = source_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        total_lines = len(source_lines)
        preview_lines = source_lines[: self.viewer_max_lines]
        preview_text = "\n".join(html.escape(line) for line in preview_lines)

        page = viewer_file.read_text(encoding="utf-8", errors="replace")
        updated = page

        updated = re.sub(
            r"(<span>Total Lines:\s*)([\d,]+)(</span>)",
            rf"\g<1>{total_lines}\g<3>",
            updated,
            count=1,
        )

        code_block = f"<pre><code>{preview_text}</code></pre>"
        updated, count = re.subn(
            r"<pre><code>.*?</code></pre>",
            code_block,
            updated,
            count=1,
            flags=re.S,
        )
        if count == 0:
            return False

        updated = re.sub(
            r'\s*<div class="truncation-notice">\(Truncated at .*? lines &mdash; full file has .*? lines\)</div>',
            "",
            updated,
            count=1,
            flags=re.S,
        )
        if total_lines > self.viewer_max_lines:
            notice = (
                f"\n    <div class=\"truncation-notice\">"
                f"(Truncated at {self.viewer_max_lines} lines &mdash; "
                f"full file has {total_lines} lines)"
                f"</div>"
            )
            updated = updated.replace("</code></pre>", f"</code></pre>{notice}", 1)

        if updated == page:
            return False
        viewer_file.write_text(updated, encoding="utf-8")
        return True

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
