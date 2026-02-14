#!/usr/bin/env python3
"""Generate pipeline_overview.html and file-viewer pages under output/docs/."""

from __future__ import annotations

import html
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


logger = logging.getLogger(__name__)


class PipelineOverviewGenerator:
    """Build a self-contained overview page for the current pipeline run."""

    CONFIG_DESCRIPTIONS: Dict[str, str] = {
        "security_config.yaml": "Security keyword/category extraction rules.",
        "attack_classes.yaml": "Attack class taxonomy and mapping metadata.",
        "k8s_kind_map.yaml": "Kubernetes kind to threat-model element mappings.",
        "threat_model_config.yaml": "Threat-model heuristics and rule mappings.",
        "pipeline_config.yaml": "Legacy pipeline configuration reference.",
        "llm_explainer_config.yaml": "LLM routing and generation settings.",
        "llm_prompt_template.txt": "Prompt template used by the LLM explainer.",
        "rule_severity.yaml": "Checkov rule severity normalization map.",
        "stride_categories.yaml": "STRIDE category mapping used for reporting.",
        "github_pages_config.yaml": "GitHub Pages publish and viewer settings.",
    }

    RESULT_DESCRIPTIONS: Dict[str, str] = {
        "security_results.jsonl": "Stage 1 output: extracted security-relevant deltas.",
        "checkov_results.json": "Stage 2 output: Checkov findings before/after.",
        "threat_model_results.json": "Stage 3A output: delta threat-model changes.",
        "full_pytm_results.json": "Stage 3B output: full native PyTM snapshot.",
        "comparison_results.json": "Stage 4 output: correlated micro/macro findings.",
        "llm_explanations.json": "Stage 5 output: grounded LLM explanations.",
        "pipeline_settings.json": "Run settings and resolved pipeline config.",
    }

    REPORT_DESCRIPTIONS: Dict[str, str] = {
        "git_security_deltas_report.html": "Extraction report with before/after diffs.",
        "comparison_report.html": "Comparison dashboard and correlated findings.",
        "llm_explainer_report.html": "Standalone LLM explanation dashboard.",
    }

    def __init__(self, repo_root: str | Path, viewer_max_lines: int = 1000) -> None:
        self.repo_root = Path(repo_root)
        self.viewer_max_lines = max(1, int(viewer_max_lines))

    def generate(self, output_dir: str | Path) -> Dict[str, object]:
        """Generate overview + docs viewer pages from current run artifacts."""
        output_path = Path(output_dir)
        docs_dir = output_path / "docs"
        docs_dir.mkdir(parents=True, exist_ok=True)

        config_items = self._build_config_items(output_path, docs_dir)
        result_items = self._build_result_items(output_path, docs_dir)
        report_items = self._build_report_items(output_path)

        overview_path = output_path / "pipeline_overview.html"
        overview_path.write_text(
            self._build_overview_html(
                config_items=config_items,
                result_items=result_items,
                report_items=report_items,
            ),
            encoding="utf-8",
        )

        generated_viewers = sum(
            1 for item in (config_items + result_items) if item.get("exists")
        )
        missing = [
            item["name"]
            for item in (config_items + result_items + report_items)
            if not item.get("exists", False)
        ]
        logger.info(
            "Generated pipeline overview at %s (viewer_pages=%d missing=%d)",
            overview_path,
            generated_viewers,
            len(missing),
        )
        return {
            "status": "ok",
            "overview_path": str(overview_path),
            "docs_dir": str(docs_dir),
            "viewer_pages_generated": generated_viewers,
            "missing_artifacts": missing,
        }

    def _build_config_items(
        self,
        output_path: Path,
        docs_dir: Path,
    ) -> List[Dict[str, object]]:
        config_dir = self.repo_root / "config"
        items: List[Dict[str, object]] = []
        for name, desc in self.CONFIG_DESCRIPTIONS.items():
            src = config_dir / name
            item = self._make_file_item(src=src, link_prefix="docs/", description=desc)
            if item["exists"]:
                self._write_viewer_page(
                    source_path=src,
                    viewer_path=docs_dir / f"{name}.html",
                    category="Config File",
                )
            items.append(item)
        return items

    def _build_result_items(
        self,
        output_path: Path,
        docs_dir: Path,
    ) -> List[Dict[str, object]]:
        items: List[Dict[str, object]] = []
        for name, desc in self.RESULT_DESCRIPTIONS.items():
            src = output_path / name
            item = self._make_file_item(src=src, link_prefix="docs/", description=desc)
            if item["exists"]:
                self._write_viewer_page(
                    source_path=src,
                    viewer_path=docs_dir / f"{name}.html",
                    category="Result File",
                )
            items.append(item)
        return items

    def _build_report_items(self, output_path: Path) -> List[Dict[str, object]]:
        items: List[Dict[str, object]] = []
        for name, desc in self.REPORT_DESCRIPTIONS.items():
            src = output_path / name
            items.append(self._make_file_item(src=src, link_prefix="", description=desc))
        return items

    @staticmethod
    def _format_size(size: int) -> str:
        units = ["B", "KB", "MB", "GB"]
        value = float(size)
        for unit in units:
            if value < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(value)} {unit}"
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{size} B"

    def _make_file_item(
        self,
        src: Path,
        link_prefix: str,
        description: str,
    ) -> Dict[str, object]:
        exists = src.exists() and src.is_file()
        line_count = 0
        size = 0
        if exists:
            content = src.read_text(encoding="utf-8", errors="replace")
            line_count = len(content.splitlines())
            size = src.stat().st_size
        return {
            "name": src.name,
            "description": description,
            "exists": exists,
            "line_count": line_count,
            "size": self._format_size(size),
            "link": f"{link_prefix}{src.name}.html" if link_prefix else src.name,
        }

    def _write_viewer_page(
        self,
        source_path: Path,
        viewer_path: Path,
        category: str,
    ) -> None:
        raw = source_path.read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()
        total_lines = len(lines)
        shown_lines = lines[: self.viewer_max_lines]
        code = "\n".join(html.escape(line) for line in shown_lines)
        truncation = ""
        if total_lines > self.viewer_max_lines:
            truncation = (
                f'<div class="truncation-notice">(Truncated at {self.viewer_max_lines} '
                f"lines &mdash; full file has {total_lines} lines)</div>"
            )

        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(source_path.name)} - Security Extractor Pipeline</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; }}
  .header {{ padding:20px 32px; border-bottom:1px solid #30363d; background:#161b22; display:flex; justify-content:space-between; align-items:center; }}
  h1 {{ margin:0; font-size:1.2rem; color:#e6edf3; }}
  .back {{ color:#58a6ff; text-decoration:none; font-size:0.9rem; }}
  .meta {{ padding:10px 32px; border-bottom:1px solid #30363d; color:#8b949e; font-size:0.85rem; }}
  .wrap {{ padding:20px 32px; }}
  pre {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; overflow:auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:0.8rem; line-height:1.45; }}
  .truncation-notice {{ margin-top:14px; color:#f0ad4e; border:1px solid #f0ad4e55; background:#1c1f26; border-radius:6px; padding:10px; text-align:center; font-size:0.84rem; }}
</style>
</head>
<body>
  <div class="header">
    <h1>{html.escape(source_path.name)}</h1>
    <a class="back" href="../pipeline_overview.html">&larr; Back to Overview</a>
  </div>
  <div class="meta">Total Lines: {total_lines} | Category: {html.escape(category)}</div>
  <div class="wrap">
    <pre><code>{code}</code></pre>
    {truncation}
  </div>
</body>
</html>
"""
        viewer_path.write_text(doc, encoding="utf-8")

    def _build_overview_html(
        self,
        config_items: List[Dict[str, object]],
        result_items: List[Dict[str, object]],
        report_items: List[Dict[str, object]],
    ) -> str:
        generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        configs_html = self._render_cards(config_items)
        results_html = self._render_cards(result_items)
        reports_html = self._render_cards(report_items)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Extractor Pipeline Overview</title>
<style>
  body {{ margin:0; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background:#0d1117; color:#c9d1d9; }}
  .header {{ padding:28px 36px; border-bottom:1px solid #30363d; background:#161b22; }}
  .header h1 {{ margin:0; color:#e6edf3; font-size:2rem; }}
  .header p {{ margin:6px 0 0; color:#8b949e; }}
  .section {{ padding:24px 36px; border-bottom:1px solid #21262d; }}
  .section h2 {{ margin:0 0 10px; color:#e6edf3; }}
  .section .desc {{ margin:0 0 14px; color:#8b949e; font-size:0.92rem; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px; }}
  .card {{ display:block; background:#161b22; border:1px solid #30363d; border-radius:10px; padding:14px; text-decoration:none; color:inherit; }}
  .card:hover {{ border-color:#58a6ff; }}
  .name {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color:#e6edf3; font-size:0.88rem; }}
  .meta {{ color:#8b949e; font-size:0.8rem; margin-top:6px; }}
  .desc-small {{ color:#8b949e; font-size:0.82rem; margin-top:8px; }}
  .missing {{ opacity:0.6; pointer-events:none; }}
</style>
</head>
<body>
  <div class="header">
    <h1>Security Extractor Pipeline Overview</h1>
    <p>Generated: {generated}</p>
  </div>
  <div class="section">
    <h2>Config Files</h2>
    <p class="desc">Pipeline configuration references. Viewer pages are capped to {self.viewer_max_lines} lines.</p>
    <div class="grid">{configs_html}</div>
  </div>
  <div class="section">
    <h2>Result Files</h2>
    <p class="desc">JSON/JSONL outputs from pipeline stages.</p>
    <div class="grid">{results_html}</div>
  </div>
  <div class="section">
    <h2>Generated HTML Reports</h2>
    <p class="desc">Primary dashboards generated in Stage 6.</p>
    <div class="grid">{reports_html}</div>
  </div>
</body>
</html>
"""

    @staticmethod
    def _render_cards(items: List[Dict[str, object]]) -> str:
        cards: List[str] = []
        for item in items:
            cls = "card" if item.get("exists") else "card missing"
            href = item["link"] if item.get("exists") else "#"
            name = html.escape(str(item["name"]))
            desc = html.escape(str(item.get("description", "")))
            meta = (
                f"{int(item['line_count']):,} lines | {item['size']}"
                if item.get("exists")
                else "Missing"
            )
            cards.append(
                f'<a class="{cls}" href="{href}">'
                f'<div class="name">{name}</div>'
                f'<div class="meta">{meta}</div>'
                f'<div class="desc-small">{desc}</div>'
                f"</a>"
            )
        return "".join(cards)
