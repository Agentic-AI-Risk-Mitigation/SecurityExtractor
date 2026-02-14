#!/usr/bin/env python3
"""Generate pipeline_overview.html and file-viewer pages under output/docs/."""

from __future__ import annotations

import html
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List


logger = logging.getLogger(__name__)


class PipelineOverviewGenerator:
    """Build a self-contained overview page for the current pipeline run."""

    CONFIG_DESCRIPTIONS: Dict[str, str] = {
        "security_config.yaml": "Keywords, IaC extensions, paths, and exclude patterns for delta extraction.",
        "rule_severity.yaml": "Checkov rule ID to severity mapping used for normalized reporting.",
        "stride_categories.yaml": "STRIDE category mappings used by attack class reporting.",
        "attack_classes.yaml": "Attack class taxonomy and source mapping definitions.",
        "k8s_kind_map.yaml": "Kubernetes resource kind to threat-model element mappings.",
        "threat_model_config.yaml": "Label flips, risky combos, hardening labels, and threat defaults.",
        "full_pytm_config.yaml": "Full native PyTM modeling semantics and protocol assumptions.",
        "comparator_scoring_config.yaml": "Comparator normalization scales and threat-signal weighting.",
        "pipeline_config.yaml": "Legacy pipeline configuration reference.",
        "llm_explainer_config.yaml": "LLM routing, fallback, token, and timeout settings.",
        "llm_prompt_template.txt": "Prompt template used by LLMExplainer.",
        "github_pages_config.yaml": "GitHub Pages publishing and viewer behavior settings.",
    }

    RESULT_DESCRIPTIONS: Dict[str, str] = {
        "security_results.jsonl": "Stage 1 output: extracted security-relevant git commit deltas.",
        "checkov_results.json": "Stage 2 output: Checkov SAST scan findings for before/after file versions.",
        "threat_model_results.json": "Stage 3A output: per-delta threat model diffs (Macro View - Delta).",
        "full_pytm_results.json": "Stage 3B output: full repository PyTM threat model snapshot (Macro View - Full).",
        "comparison_results.json": "Stage 4 output: correlated Micro+Macro findings with composite scores and CSI flags.",
        "llm_explanations.json": "Stage 5 output: LLM-generated grounded security explanations for top findings.",
        "pipeline_settings.json": "Pipeline settings snapshot persisted for the run.",
    }

    REPORT_DESCRIPTIONS: Dict[str, str] = {
        "git_security_deltas_report.html": (
            "Extraction report: interactive view of all security-relevant git commit deltas with IaC diffs."
        ),
        "comparison_report.html": (
            "Comparison dashboard: attack class breakdown, severity distribution, and score ranking."
        ),
        "llm_explainer_report.html": (
            "LLM explanation report: grounded security explanations, posture, and recommendations."
        ),
    }

    COMPONENT_ROWS: List[Dict[str, object]] = [
        {
            "stage": "Orchestrator",
            "component": "PipelineRunner.py",
            "description": "Master orchestrator - coordinates all stages, config loading, and run archive output.",
            "config_files": ["pipeline_config.yaml", "llm_explainer_config.yaml", "github_pages_config.yaml"],
            "result_files": ["pipeline_settings.json"],
            "orchestrator": True,
        },
        {
            "stage": "Stage 1",
            "component": "SecurityDeltaExtractor.py",
            "description": "Extracts security-relevant git commit deltas with IaC file diffs.",
            "config_files": ["security_config.yaml"],
            "result_files": ["security_results.jsonl"],
        },
        {
            "stage": "Stage 2",
            "component": "CheckovScanner.py",
            "description": "Runs Checkov scanner on before/after versions (Micro View).",
            "config_files": ["rule_severity.yaml", "attack_classes.yaml"],
            "result_files": ["checkov_results.json"],
        },
        {
            "stage": "Stage 3A",
            "component": "DeltaThreatModelDiffGenerator.py",
            "description": "Generates per-delta threat model diffs (Macro View - Delta).",
            "config_files": ["threat_model_config.yaml", "k8s_kind_map.yaml", "stride_categories.yaml"],
            "result_files": ["threat_model_results.json"],
        },
        {
            "stage": "Stage 3B",
            "component": "FullPyTMGenerator.py",
            "description": "Runs native PyTM on a full repository snapshot (Macro View - Full).",
            "config_files": ["full_pytm_config.yaml", "k8s_kind_map.yaml", "threat_model_config.yaml"],
            "result_files": ["full_pytm_results.json"],
        },
        {
            "stage": "Stage 4",
            "component": "VulnerabilityComparator.py",
            "description": "Correlates Micro + Macro findings and computes CSI-oriented ranking.",
            "config_files": ["attack_classes.yaml", "comparator_scoring_config.yaml"],
            "result_files": ["comparison_results.json"],
        },
        {
            "stage": "Stage 5",
            "component": "LLMExplainer.py",
            "description": "Explains top findings through OpenRouter-backed LLM inference.",
            "config_files": ["llm_explainer_config.yaml", "llm_prompt_template.txt"],
            "result_files": ["llm_explanations.json"],
        },
        {
            "stage": "Stage 6",
            "component": "ExtractionReporter.py",
            "description": "Generates the extraction HTML report.",
            "config_files": [],
            "result_files": ["git_security_deltas_report.html"],
        },
        {
            "stage": "Stage 6",
            "component": "ComparisonReporter.py",
            "description": "Generates the comparison dashboard HTML report.",
            "config_files": [],
            "result_files": ["comparison_report.html"],
        },
        {
            "stage": "Stage 6",
            "component": "LLMExplainerReporter.py",
            "description": "Generates standalone HTML report for LLM explanations.",
            "config_files": [],
            "result_files": ["llm_explainer_report.html"],
        },
    ]

    def __init__(self, repo_root: str | Path, viewer_max_lines: int = 1000) -> None:
        self.repo_root = Path(repo_root)
        self.viewer_max_lines = max(1, int(viewer_max_lines))

    def generate(self, output_dir: str | Path) -> Dict[str, object]:
        """Generate overview + docs viewer pages from current run artifacts."""
        output_path = Path(output_dir)
        docs_dir = output_path / "docs"
        docs_dir.mkdir(parents=True, exist_ok=True)

        config_items = self._build_config_items(docs_dir)
        result_items = self._build_result_items(output_path, docs_dir)
        report_items = self._build_report_items(output_path)

        overview_path = output_path / "pipeline_overview.html"
        overview_path.write_text(
            self._build_overview_html(
                generated=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
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

    def _build_config_items(self, docs_dir: Path) -> List[Dict[str, object]]:
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
                f"lines - full file has {total_lines} lines)</div>"
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
        generated: str,
        config_items: List[Dict[str, object]],
        result_items: List[Dict[str, object]],
        report_items: List[Dict[str, object]],
    ) -> str:
        config_map = {str(i["name"]): i for i in config_items}
        result_map = {str(i["name"]): i for i in result_items}
        report_map = {str(i["name"]): i for i in report_items}
        artifact_map = {}
        artifact_map.update(config_map)
        artifact_map.update(result_map)
        artifact_map.update(report_map)

        component_rows_html = self._render_component_rows(artifact_map)
        config_cards_html = self._render_cards(config_items, report_mode=False)
        result_cards_html = self._render_cards(result_items, report_mode=False)
        report_cards_html = self._render_cards(report_items, report_mode=True)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Extractor Pipeline Overview</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    min-height: 100vh;
    line-height: 1.6;
  }}
  a {{ color: #4fc3f7; text-decoration: none; transition: color 0.2s; }}
  a:hover {{ color: #81d4fa; text-decoration: underline; }}

  .main-header {{
    background: linear-gradient(135deg, #161b22 0%, #1a237e 50%, #0d1117 100%);
    border-bottom: 2px solid #30363d;
    padding: 40px 48px;
    text-align: center;
  }}
  .main-header h1 {{ font-size: 2.2rem; font-weight: 700; color: #e6edf3; letter-spacing: -0.5px; margin-bottom: 8px; }}
  .main-header .subtitle {{ color: #8b949e; font-size: 1rem; margin-bottom: 6px; }}
  .main-header .timestamp {{ color: #4fc3f7; font-size: 0.85rem; font-family: 'JetBrains Mono', 'Fira Code', monospace; }}
  .shield-icon {{ display: inline-block; width: 36px; height: 36px; vertical-align: middle; margin-right: 10px; }}

  .nav-bar {{
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 0 48px;
    display: flex;
    gap: 0;
    overflow-x: auto;
  }}
  .nav-bar a {{
    padding: 14px 20px;
    color: #8b949e;
    font-size: 0.9rem;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
    white-space: nowrap;
  }}
  .nav-bar a:hover {{
    color: #e6edf3;
    border-bottom-color: #4fc3f7;
    text-decoration: none;
    background: #1c2129;
  }}

  .section {{ max-width: 1400px; margin: 0 auto; padding: 40px 48px; }}
  .section-title {{ font-size: 1.5rem; font-weight: 600; color: #e6edf3; margin-bottom: 8px; }}
  .section-desc {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 24px; }}
  .divider {{ border: 0; border-top: 1px solid #21262d; margin: 0; }}

  .table-wrapper {{ overflow-x: auto; border-radius: 10px; border: 1px solid #30363d; }}
  table.pipeline-table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  table.pipeline-table thead {{ background: #161b22; }}
  table.pipeline-table th {{ padding: 14px 16px; text-align: left; font-weight: 600; color: #e6edf3; border-bottom: 2px solid #30363d; white-space: nowrap; }}
  table.pipeline-table td {{ padding: 12px 16px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  table.pipeline-table tr:hover {{ background: #161b2233; }}
  table.pipeline-table .stage-badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 10px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    background: #4fc3f722;
    color: #4fc3f7;
    border: 1px solid #4fc3f744;
    white-space: nowrap;
  }}
  table.pipeline-table .stage-orchestrator {{ background:#ffa72622; color:#ffa726; border-color:#ffa72644; }}
  table.pipeline-table .component-name {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.82rem; color: #e6edf3; font-weight: 600; }}
  table.pipeline-table .desc-text {{ color: #8b949e; font-size: 0.82rem; }}
  table.pipeline-table .file-link {{ display: inline-block; margin: 2px 0; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.78rem; }}
  table.pipeline-table .file-size {{ color: #484f58; font-size: 0.72rem; margin-left: 4px; }}
  table.pipeline-table .missing-file {{ color: #6e7681; font-size: 0.78rem; font-family: 'JetBrains Mono', 'Fira Code', monospace; display:block; margin:2px 0; }}

  .card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }}
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    transition: all 0.25s;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }}
  .card:hover {{ border-color: #4fc3f7; box-shadow: 0 4px 16px rgba(79, 195, 247, 0.08); transform: translateY(-2px); }}
  .card .card-title {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.9rem; color: #e6edf3; font-weight: 600; }}
  .card .card-meta {{ color: #8b949e; font-size: 0.8rem; display: flex; gap: 16px; flex-wrap: wrap; }}
  .card .card-badge {{ display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.4px; }}
  .card .badge-yaml {{ background: #4fc3f722; color: #4fc3f7; border: 1px solid #4fc3f733; }}
  .card .badge-json {{ background: #66bb6a22; color: #66bb6a; border: 1px solid #66bb6a33; }}
  .card .badge-html {{ background: #ff726622; color: #ff7266; border: 1px solid #ff726633; }}
  .card .badge-txt {{ background: #ffa72622; color: #ffa726; border: 1px solid #ffa72633; }}
  .card .card-desc {{ color: #8b949e; font-size: 0.82rem; flex-grow: 1; }}
  .card .card-link {{ display: flex; align-items: center; gap: 6px; font-size: 0.82rem; margin-top: 4px; }}

  .report-card {{ background: linear-gradient(135deg, #161b22 0%, #1a1f2e 100%); border: 1px solid #ff726644; }}
  .report-card:hover {{ border-color: #ff7266; box-shadow: 0 4px 16px rgba(255, 114, 102, 0.1); }}
  .report-card .card-title {{ color: #ff7266; }}

  .missing-card {{ opacity: 0.55; filter: grayscale(0.2); }}
  .missing-card .card-link {{ color: #8b949e; }}

  .main-footer {{ text-align: center; padding: 28px 48px; color: #484f58; font-size: 0.8rem; border-top: 1px solid #21262d; margin-top: 20px; }}
  .main-footer .footer-brand {{ color: #30363d; font-size: 0.7rem; margin-top: 6px; }}

  .orchestrator-banner {{
    background: linear-gradient(135deg, #1a237e33 0%, #16213e 100%);
    border: 1px solid #4fc3f744;
    border-radius: 10px;
    padding: 20px 28px;
    margin-bottom: 28px;
    display: flex;
    align-items: center;
    gap: 16px;
  }}
  .orchestrator-banner .orch-icon {{
    width: 48px;
    height: 48px;
    background: #4fc3f722;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.4rem;
    flex-shrink: 0;
  }}
  .orchestrator-banner .orch-text h3 {{ color: #e6edf3; font-size: 1rem; font-weight: 600; margin-bottom: 2px; }}
  .orchestrator-banner .orch-text h3 code {{ color: #4fc3f7; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.9rem; background: #4fc3f711; padding: 2px 6px; border-radius: 4px; }}
  .orchestrator-banner .orch-text p {{ color: #8b949e; font-size: 0.85rem; }}

  @media (max-width: 900px) {{
    .main-header, .section {{ padding: 28px 20px; }}
    .nav-bar {{ padding: 0 20px; }}
    .main-header h1 {{ font-size: 1.7rem; }}
    table.pipeline-table th, table.pipeline-table td {{ padding: 10px; }}
  }}
</style>
</head>
<body>
<header class="main-header">
  <h1>
    <svg class="shield-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="#4fc3f722" stroke="#4fc3f7" stroke-width="1.5"></path>
      <path d="M10 12l2 2 4-4" stroke="#4fc3f7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>
    Security Extractor Pipeline Overview
  </h1>
  <p class="subtitle">Comprehensive security analysis pipeline for Kubernetes IaC repositories</p>
  <p class="timestamp" id="header-timestamp">Generated: {generated}</p>
</header>

<nav class="nav-bar">
  <a href="#components-section">Components</a>
  <a href="#config-section">Config Files</a>
  <a href="#results-section">Result Files</a>
  <a href="#reports-section">HTML Reports</a>
</nav>

<div class="section" id="components-section">
  <h2 class="section-title">Pipeline Components</h2>
  <p class="section-desc">Pipeline components in execution order, with config inputs and produced artifacts.</p>

  <div class="orchestrator-banner">
    <div class="orch-icon">&#9881;</div>
    <div class="orch-text">
      <h3>Orchestrator: <code>PipelineRunner.py</code></h3>
      <p>Master orchestrator - coordinates all pipeline stages, config loading, and publishing workflow.</p>
    </div>
  </div>

  <div class="table-wrapper">
    <table class="pipeline-table">
      <thead>
        <tr>
          <th>Stage</th>
          <th>Component</th>
          <th>Description</th>
          <th>Config Files</th>
          <th>Result Files</th>
        </tr>
      </thead>
      <tbody>
        {component_rows_html}
      </tbody>
    </table>
  </div>
</div>

<hr class="divider">

<div class="section" id="config-section">
  <h2 class="section-title">Configuration Files</h2>
  <p class="section-desc">YAML and text configuration files controlling extraction, threat modeling, scoring, LLM, and publish behavior.</p>
  <div class="card-grid">{config_cards_html}</div>
</div>

<hr class="divider">

<div class="section" id="results-section">
  <h2 class="section-title">Result Files</h2>
  <p class="section-desc">JSON and JSONL outputs from each pipeline stage. Viewer pages are capped to {self.viewer_max_lines} lines.</p>
  <div class="card-grid">{result_cards_html}</div>
</div>

<hr class="divider">

<div class="section" id="reports-section">
  <h2 class="section-title">Generated HTML Reports</h2>
  <p class="section-desc">Interactive HTML reports generated by Stage 6 reporters.</p>
  <div class="card-grid">{report_cards_html}</div>
</div>

<footer class="main-footer">
  <div>Security Extractor Pipeline Overview - Generated <span id="footer-timestamp">{generated}</span></div>
  <div class="footer-brand">SecurityExtractor | Kubernetes IaC Security Analysis</div>
</footer>

</body>
</html>"""

    def _render_component_rows(self, artifact_map: Dict[str, Dict[str, object]]) -> str:
        rows: List[str] = []
        for row in self.COMPONENT_ROWS:
            stage = html.escape(str(row.get("stage", "")))
            component = html.escape(str(row.get("component", "")))
            description = html.escape(str(row.get("description", "")))
            config_files = row.get("config_files", []) or []
            result_files = row.get("result_files", []) or []
            orchestrator = bool(row.get("orchestrator"))
            badge_cls = "stage-badge stage-orchestrator" if orchestrator else "stage-badge"
            configs_html = self._render_component_file_links(
                names=[str(n) for n in config_files],
                artifact_map=artifact_map,
                empty_text="&mdash;",
            )
            results_html = self._render_component_file_links(
                names=[str(n) for n in result_files],
                artifact_map=artifact_map,
                empty_text="&mdash;",
            )
            rows.append(
                "<tr>"
                f'<td><span class="{badge_cls}">{stage}</span></td>'
                f'<td class="component-name">{component}</td>'
                f'<td class="desc-text">{description}</td>'
                f"<td>{configs_html}</td>"
                f"<td>{results_html}</td>"
                "</tr>"
            )
        return "".join(rows)

    def _render_component_file_links(
        self,
        names: List[str],
        artifact_map: Dict[str, Dict[str, object]],
        empty_text: str,
    ) -> str:
        if not names:
            return f'<span class="desc-text">{empty_text}</span>'
        out: List[str] = []
        for name in names:
            item = artifact_map.get(name)
            safe_name = html.escape(name)
            if not item or not item.get("exists"):
                out.append(f'<span class="missing-file">{safe_name} (missing)</span>')
                continue
            link = html.escape(str(item.get("link", "#")))
            size = html.escape(str(item.get("size", "")))
            lines = int(item.get("line_count", 0))
            line_part = f", {lines:,} lines" if lines > 0 else ""
            out.append(
                f'<a href="{link}" class="file-link">{safe_name}</a>'
                f'<span class="file-size">({size}{line_part})</span><br>'
            )
        return "".join(out)

    def _render_cards(
        self,
        items: List[Dict[str, object]],
        report_mode: bool,
    ) -> str:
        cards: List[str] = []
        for item in items:
            exists = bool(item.get("exists"))
            href = html.escape(str(item.get("link", "#"))) if exists else "#"
            name = html.escape(str(item.get("name", "")))
            desc = html.escape(str(item.get("description", "")))
            size = html.escape(str(item.get("size", "")))
            lines = int(item.get("line_count", 0))
            line_meta = f"{lines:,} lines" if lines > 0 else "0 lines"

            badge_text, badge_cls = self._file_badge(str(item.get("name", "")))
            card_classes = ["card"]
            if report_mode:
                card_classes.append("report-card")
            if not exists:
                card_classes.append("missing-card")
            card_class_str = " ".join(card_classes)

            action_text = "Open Report ->" if report_mode else "Open Viewer ->"
            if not exists:
                action_text = "Artifact Missing"
            link_style_attr = ' style="color:#ff7266;"' if report_mode else ""

            cards.append(
                f'<a href="{href}" style="text-decoration:none;color:inherit;{"pointer-events:none;" if not exists else ""}">'
                f'  <div class="{card_class_str}">'
                f'    <div><span class="card-badge {badge_cls}">{html.escape(badge_text)}</span></div>'
                f'    <div class="card-title">{name}</div>'
                f'    <div class="card-desc">{desc}</div>'
                f'    <div class="card-meta"><span>{line_meta}</span><span>{size}</span></div>'
                f'    <div class="card-link"{link_style_attr}>{action_text}</div>'
                f"  </div>"
                f"</a>"
            )
        return "".join(cards)

    @staticmethod
    def _file_badge(filename: str) -> tuple[str, str]:
        name = filename.lower()
        if name.endswith(".yaml") or name.endswith(".yml"):
            return "YAML", "badge-yaml"
        if name.endswith(".jsonl"):
            return "JSONL", "badge-json"
        if name.endswith(".json"):
            return "JSON", "badge-json"
        if name.endswith(".html"):
            return "HTML", "badge-html"
        if name.endswith(".txt"):
            return "TXT", "badge-txt"
        return "FILE", "badge-txt"
