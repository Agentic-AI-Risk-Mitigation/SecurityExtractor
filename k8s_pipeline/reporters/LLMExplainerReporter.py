#!/usr/bin/env python3
"""LLMExplainerReporter.py -- Standalone HTML report for LLM explanation output."""

import json
import logging
from datetime import datetime
from html import escape
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class LLMExplainerReporter:
    """Render `llm_explanations.json` to a dedicated HTML report."""

    def __init__(self, output_file: str, repo_url: str) -> None:
        self.output_file = output_file
        self.repo_url = repo_url.rstrip("/")

    def generate(
        self,
        result: Optional[Dict[str, Any]] = None,
        json_file: Optional[str] = None,
    ) -> str:
        """Build the HTML report and write it to disk."""
        if result is not None and json_file is not None:
            raise ValueError("Provide either 'result' or 'json_file', not both.")
        if result is None and json_file is None:
            raise ValueError("Provide either 'result' or 'json_file'.")

        if json_file is not None:
            logger.info("Loading LLM explanation result from %s", json_file)
            with open(json_file, "r", encoding="utf-8") as fh:
                result = json.load(fh)
            source_label = json_file
        else:
            source_label = "in-memory data"

        html = self._build_html(result, source_label)
        with open(self.output_file, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info("Saved LLM explainer report to %s", self.output_file)
        logger.info("LLM explainer report items: %d", len(result.get("items", [])))
        return self.output_file

    def _build_html(self, result: Dict[str, Any], source_label: str) -> str:
        status = escape(str(result.get("status", "unknown")))
        posture = escape(str(result.get("overall_posture", "unknown")))
        model = escape(str(result.get("model", "-")))
        provider = escape(str(result.get("provider", "-")))
        generated_at = escape(str(result.get("generated_at", "-")))
        top_requested = int(result.get("top_n_requested", 0))
        top_used = int(result.get("top_n_used", 0))
        summary = escape(str(result.get("executive_summary", "")))

        limitations = result.get("limitations", []) or []
        limitations_html = (
            "".join(f"<li>{escape(str(item))}</li>" for item in limitations)
            if limitations
            else "<li>None reported.</li>"
        )
        ignored_findings = result.get("ignored_findings", []) or []

        items = result.get("items", []) or []
        rows = "\n".join(self._render_item_row(item) for item in items[:20])
        items_html = (
            f"""
    <table>
        <thead>
            <tr>
                <th style="width:5%">#</th>
                <th style="width:18%">Commit / File</th>
                <th style="width:8%">Severity</th>
                <th style="width:9%">Attack Class</th>
                <th style="width:8%">Score</th>
                <th style="width:26%">Impact</th>
                <th style="width:26%">Recommended Action</th>
            </tr>
        </thead>
        <tbody>
{rows}
        </tbody>
    </table>
"""
            if rows
            else '<p class="empty">No LLM explanation items available.</p>'
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Security Explanation Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            padding: 20px;
            background: #f7f9fc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            font-size: 13px;
            line-height: 1.45;
            color: #1f2937;
        }}
        h1 {{
            margin: 0 0 8px 0;
            color: #0b3d91;
            font-size: 24px;
        }}
        h2 {{
            margin: 24px 0 10px 0;
            font-size: 16px;
            color: #2c3e50;
            border-bottom: 2px solid #0b3d91;
            padding-bottom: 4px;
        }}
        .subtitle {{
            color: #5b6472;
            font-size: 12px;
            margin-bottom: 14px;
        }}
        .cards {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 18px;
        }}
        .card {{
            background: #ffffff;
            border: 1px solid #dbe2ea;
            border-radius: 8px;
            padding: 12px;
            min-width: 150px;
            flex: 1;
        }}
        .value {{
            font-size: 24px;
            font-weight: 700;
            color: #0b3d91;
        }}
        .label {{
            font-size: 10px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }}
        .section-note {{
            background: #e8eefb;
            border-radius: 8px;
            padding: 12px;
            color: #1f2937;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border: 1px solid #dbe2ea;
        }}
        th {{
            background: #2c3e50;
            color: #ffffff;
            text-align: left;
            padding: 8px;
            font-size: 11px;
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 8px;
            border: 1px solid #e5e7eb;
            vertical-align: top;
            font-size: 12px;
        }}
        tr:nth-child(even) {{ background: #f9fbff; }}
        .commit-sha {{
            display: inline-block;
            background: #e3f2fd;
            border-radius: 3px;
            padding: 2px 6px;
            font-size: 11px;
        }}
        .commit-sha a {{
            color: #0b3d91;
            text-decoration: none;
        }}
        .commit-sha a:hover {{ text-decoration: underline; }}
        .file-path {{
            margin-top: 4px;
            font-size: 10px;
            color: #5b6472;
            word-break: break-all;
        }}
        .badge {{
            display: inline-block;
            border-radius: 3px;
            padding: 2px 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .sev-critical {{ background: #b71c1c; color: #fff; }}
        .sev-high {{ background: #d32f2f; color: #fff; }}
        .sev-medium {{ background: #f57c00; color: #fff; }}
        .sev-low {{ background: #388e3c; color: #fff; }}
        .sev-info {{ background: #455a64; color: #fff; }}
        .sev-unknown {{ background: #757575; color: #fff; }}
        .empty {{
            color: #8a94a6;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <h1>LLM Security Explanation Report</h1>
    <p class="subtitle">
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} |
        Source: {escape(source_label)}
    </p>

    <div class="cards">
        <div class="card">
            <div class="value">{status}</div>
            <div class="label">Status</div>
        </div>
        <div class="card">
            <div class="value">{posture}</div>
            <div class="label">Overall Posture</div>
        </div>
        <div class="card">
            <div class="value">{top_used}</div>
            <div class="label">Explained Items</div>
        </div>
        <div class="card">
            <div class="value">{top_requested}</div>
            <div class="label">Top-N Requested</div>
        </div>
    </div>

    <div class="section-note">
        Provider: <strong>{provider}</strong> |
        Model: <strong>{model}</strong> |
        LLM generated_at: {generated_at}
    </div>

    <h2>Executive Summary</h2>
    <p>{summary or '<span class="empty">No executive summary available.</span>'}</p>

    <h2>Explained Findings</h2>
    {items_html}

    <h2>Limitations</h2>
    <ul>
        {limitations_html}
    </ul>
    <h2>Ignored Findings</h2>
    <p>{len(ignored_findings)} findings were explicitly ignored by the LLM output.</p>
</body>
</html>
"""

    def _render_item_row(self, item: Dict[str, Any]) -> str:
        rank = int(item.get("rank", 0))
        commit_sha = escape(str(item.get("commit_sha", "")))
        file_path = escape(str(item.get("file_path", "")))
        severity = str(item.get("severity", "unknown")).lower()
        severity_text = escape(severity.upper())
        attack_class = escape(str(item.get("attack_class", "")))
        impact = escape(str(item.get("security_impact", "")))
        action = escape(str(item.get("recommended_action", "")))
        score = float(item.get("composite_score", 0.0))

        short_sha = commit_sha[:8] if commit_sha else ""
        commit_link = f"{self.repo_url}/commit/{commit_sha}" if commit_sha else "#"

        return f"""
            <tr>
                <td>{rank}</td>
                <td>
                    <span class="commit-sha"><a href="{commit_link}" target="_blank">{short_sha or "-"}</a></span>
                    <div class="file-path">{file_path or "-"}</div>
                </td>
                <td><span class="badge sev-{escape(severity)}">{severity_text}</span></td>
                <td>{attack_class or "-"}</td>
                <td>{score:.2f}</td>
                <td>{impact or "-"}</td>
                <td>{action or "-"}</td>
            </tr>
"""
