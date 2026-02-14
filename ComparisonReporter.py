"""
ComparisonReporter.py - HTML Report for Micro vs Macro Comparison
==================================================================

Creates a self-contained HTML dashboard showing how Checkov (Micro View)
findings compare with Threat Model (Macro View) findings for each
security-relevant git delta.

Usage (from memory):
    reporter = ComparisonReporter("report.html", repo_url, ac_config)
    reporter.generate(results=comparison_data)

Usage (from file):
    reporter = ComparisonReporter("report.html", repo_url, ac_config)
    reporter.generate(json_file="comparison_results.json")
"""

import json
from collections import Counter
from datetime import datetime
from html import escape
from typing import Any, Dict, List, Optional


class ComparisonReporter:
    """Generate an HTML report from comparison results.

    Parameters
    ----------
    output_file : str
        Path where the HTML report will be written.
    repo_url : str
        Base GitHub URL for commit links.
    attack_classes_config : dict
        Parsed ``attack_classes.yaml`` for AC name lookups.
    """

    def __init__(
        self,
        output_file: str,
        repo_url: str,
        attack_classes_config: dict,
    ) -> None:
        self.output_file = output_file
        self.repo_url = repo_url
        self.ac_names: Dict[str, str] = {}
        for ac in attack_classes_config.get("attack_classes", []):
            self.ac_names[ac["id"]] = ac["name"]

    def generate(
        self,
        results: Optional[List[Dict]] = None,
        json_file: Optional[str] = None,
    ) -> str:
        """Build the HTML report and write to disk.

        Provide exactly one of ``results`` (in-memory) or ``json_file``.
        Returns the output file path.
        """
        if results is not None and json_file is not None:
            raise ValueError(
                "Provide either 'results' or 'json_file', not both."
            )
        if results is None and json_file is None:
            raise ValueError(
                "Provide either 'results' or 'json_file'."
            )

        if json_file is not None:
            with open(json_file, "r", encoding="utf-8") as f:
                results = json.load(f)
            source_label = json_file
        else:
            source_label = "in-memory data"

        html = self._build_html(results, source_label)
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"Saved comparison report to {self.output_file}")
        return self.output_file

    # -----------------------------------------------------------------
    # HTML assembly
    # -----------------------------------------------------------------
    def _build_html(
        self, results: List[Dict], source_label: str
    ) -> str:
        """Assemble the complete HTML document."""
        summary = self._compute_summary(results)
        summary_html = self._render_summary(summary)
        ac_html = self._render_ac_breakdown(summary["ac_distribution"])
        macro_only = [r for r in results if r.get("macro_only")]
        macro_html = self._render_macro_only(macro_only)
        detail_rows = "\n".join(
            self._render_detail_row(i, r)
            for i, r in enumerate(results, 1)
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Comparison Report - Micro vs Macro</title>
    <style>
        * {{ box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                         Roboto, monospace;
            margin: 0;
            padding: 20px;
            background: #fafafa;
            font-size: 13px;
            line-height: 1.4;
        }}

        h1 {{
            font-size: 22px;
            margin-bottom: 5px;
            color: #1a237e;
        }}

        h2 {{
            font-size: 16px;
            color: #333;
            margin-top: 30px;
            margin-bottom: 10px;
            border-bottom: 2px solid #1a237e;
            padding-bottom: 4px;
        }}

        .subtitle {{
            color: #666;
            margin-bottom: 20px;
            font-size: 12px;
        }}

        /* Summary cards */
        .cards {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 24px;
        }}

        .card {{
            flex: 1;
            min-width: 140px;
            background: white;
            border-radius: 8px;
            padding: 16px;
            border: 1px solid #e0e0e0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }}

        .card-value {{
            font-size: 28px;
            font-weight: 700;
            color: #1a237e;
        }}

        .card-label {{
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .card.regression .card-value {{ color: #c62828; }}
        .card.improvement .card-value {{ color: #2e7d32; }}
        .card.macro-only .card-value {{ color: #e65100; }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-bottom: 20px;
        }}

        th {{
            background: #2c3e50;
            color: white;
            padding: 10px 8px;
            text-align: left;
            font-weight: 600;
            font-size: 11px;
            position: sticky;
            top: 0;
            z-index: 10;
        }}

        td {{
            padding: 8px;
            border: 1px solid #ddd;
            vertical-align: top;
            font-size: 12px;
        }}

        tr:nth-child(even) {{ background: #f9f9f9; }}
        tr:hover {{ background: #fff3cd; }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-regression {{
            background: #ffcdd2;
            color: #c62828;
        }}

        .badge-improvement {{
            background: #c8e6c9;
            color: #2e7d32;
        }}

        .badge-neutral {{
            background: #e0e0e0;
            color: #616161;
        }}

        .badge-csi {{
            background: #fff3e0;
            color: #e65100;
        }}

        .badge-macro {{
            background: #e8eaf6;
            color: #283593;
        }}

        .badge-micro {{
            background: #fce4ec;
            color: #880e4f;
        }}

        .badge-severity {{
            font-size: 9px;
            padding: 1px 5px;
        }}

        .sev-CRITICAL {{ background: #b71c1c; color: white; }}
        .sev-HIGH {{ background: #e53935; color: white; }}
        .sev-MEDIUM {{ background: #ff9800; color: white; }}
        .sev-LOW {{ background: #4caf50; color: white; }}

        /* AC table */
        .ac-bar {{
            height: 14px;
            background: #1a237e;
            border-radius: 2px;
            min-width: 2px;
        }}

        .ac-cell {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* Commit info */
        .commit-sha {{
            font-family: Consolas, Monaco, monospace;
            font-size: 11px;
            background: #e3f2fd;
            padding: 2px 6px;
            border-radius: 3px;
        }}

        .commit-sha a {{
            color: #1565c0;
            text-decoration: none;
        }}

        .commit-sha a:hover {{ text-decoration: underline; }}

        .file-path {{
            font-family: Consolas, Monaco, monospace;
            font-size: 10px;
            color: #666;
            word-break: break-all;
        }}

        .commit-msg {{
            font-size: 11px;
            color: #333;
            margin: 3px 0;
            word-wrap: break-word;
        }}

        .score-bar {{
            display: inline-block;
            height: 10px;
            background: #1a237e;
            border-radius: 2px;
            min-width: 2px;
        }}

        .keyword {{
            display: inline-block;
            background: #fff3e0;
            color: #e65100;
            padding: 1px 5px;
            border-radius: 3px;
            font-size: 10px;
            margin: 1px;
        }}

        .finding {{
            font-size: 10px;
            padding: 2px 0;
            border-bottom: 1px solid #f0f0f0;
        }}

        .empty {{
            color: #999;
            font-style: italic;
            font-size: 11px;
        }}

        .section-note {{
            background: #e8eaf6;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 11px;
            color: #333;
            margin-bottom: 16px;
        }}

        footer {{
            margin-top: 20px;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 6px;
            font-size: 11px;
            color: #666;
        }}
    </style>
</head>
<body>
    <h1>Security Posture Comparison Report</h1>
    <p class="subtitle">
        {len(results)} deltas analyzed |
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} |
        Source: {escape(source_label)}
    </p>

    {summary_html}

    <h2>Attack Class Distribution</h2>
    {ac_html}

    <h2>Macro-Only Detections</h2>
    <div class="section-note">
        These findings were detected by the <strong>Threat Model (Macro View)</strong>
        but <strong>NOT</strong> by Checkov (Micro View).  They represent gaps in
        static analysis coverage.
    </div>
    {macro_html}

    <h2>All Correlated Deltas</h2>
    <table>
        <thead>
            <tr>
                <th style="width:20%">Commit / File</th>
                <th style="width:18%">Micro View (Checkov)</th>
                <th style="width:22%">Macro View (Threat Model)</th>
                <th style="width:10%">Attack Class</th>
                <th style="width:10%">Score</th>
                <th style="width:10%">Direction</th>
                <th style="width:10%">Flags</th>
            </tr>
        </thead>
        <tbody>
{detail_rows}
        </tbody>
    </table>

    <footer>
        <strong>How to read this report:</strong><br>
        &bull; <strong>Micro View</strong> = Checkov SAST findings
            (specific misconfigurations like CKV_K8S_1)<br>
        &bull; <strong>Macro View</strong> = Threat model findings
            (high-level posture changes like label flips)<br>
        &bull; <span class="badge badge-macro">MACRO</span> = detected by
            threat model only (Checkov blind spot)<br>
        &bull; <span class="badge badge-micro">MICRO</span> = detected by
            Checkov only (no threat model counterpart)<br>
        &bull; <span class="badge badge-csi">CSI</span> = Commit of
            Security Interest (composite score &ge; threshold)<br>
        &bull; <strong>Score</strong> = weighted composite of keyword,
            Checkov, and threat model signals
    </footer>
</body>
</html>"""

    # -----------------------------------------------------------------
    # Summary computation
    # -----------------------------------------------------------------
    def _compute_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Aggregate statistics from comparison results."""
        total = len(results)
        regressions = sum(
            1 for r in results
            if r.get("posture_direction") == "regression"
        )
        improvements = sum(
            1 for r in results
            if r.get("posture_direction") == "improvement"
        )
        neutral = total - regressions - improvements
        csi_count = sum(1 for r in results if r.get("is_csi"))
        macro_only_count = sum(1 for r in results if r.get("macro_only"))
        micro_only_count = sum(1 for r in results if r.get("micro_only"))

        # AC distribution
        ac_counter: Counter = Counter()
        for r in results:
            ac = r.get("attack_class", "")
            if ac:
                ac_counter[ac] += 1

        return {
            "total": total,
            "regressions": regressions,
            "improvements": improvements,
            "neutral": neutral,
            "csi_count": csi_count,
            "macro_only_count": macro_only_count,
            "micro_only_count": micro_only_count,
            "ac_distribution": dict(
                ac_counter.most_common()
            ),
        }

    # -----------------------------------------------------------------
    # Section renderers
    # -----------------------------------------------------------------
    def _render_summary(self, summary: Dict[str, Any]) -> str:
        """Render summary statistics as HTML cards."""
        return f"""
    <div class="cards">
        <div class="card">
            <div class="card-value">{summary['total']}</div>
            <div class="card-label">Total Deltas</div>
        </div>
        <div class="card regression">
            <div class="card-value">{summary['regressions']}</div>
            <div class="card-label">Regressions</div>
        </div>
        <div class="card improvement">
            <div class="card-value">{summary['improvements']}</div>
            <div class="card-label">Improvements</div>
        </div>
        <div class="card">
            <div class="card-value">{summary['csi_count']}</div>
            <div class="card-label">CSI Flagged</div>
        </div>
        <div class="card macro-only">
            <div class="card-value">{summary['macro_only_count']}</div>
            <div class="card-label">Macro-Only</div>
        </div>
        <div class="card">
            <div class="card-value">{summary['micro_only_count']}</div>
            <div class="card-label">Micro-Only</div>
        </div>
    </div>"""

    def _render_ac_breakdown(
        self, ac_dist: Dict[str, int]
    ) -> str:
        """Render attack class distribution as an HTML table."""
        if not ac_dist:
            return '<p class="empty">No attack classes detected.</p>'

        max_count = max(ac_dist.values()) if ac_dist else 1
        rows = []
        for ac_id, count in sorted(ac_dist.items()):
            name = self.ac_names.get(ac_id, ac_id)
            bar_width = int((count / max_count) * 200)
            rows.append(f"""
            <tr>
                <td><strong>{escape(ac_id)}</strong></td>
                <td>{escape(name)}</td>
                <td>{count}</td>
                <td>
                    <div class="ac-cell">
                        <div class="ac-bar"
                             style="width:{bar_width}px"></div>
                    </div>
                </td>
            </tr>""")

        return f"""
    <table>
        <thead>
            <tr>
                <th style="width:8%">ID</th>
                <th style="width:30%">Attack Class</th>
                <th style="width:8%">Count</th>
                <th>Distribution</th>
            </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
    </table>"""

    def _render_macro_only(
        self, macro_results: List[Dict]
    ) -> str:
        """Render section highlighting Macro-only detections."""
        if not macro_results:
            return '<p class="empty">No macro-only detections found.</p>'

        rows = []
        for r in macro_results:
            sha = r.get("commit_sha", "")[:8]
            fpath = r.get("file_path", "")
            link = (
                f"{self.repo_url}/commit/{r.get('commit_sha', '')}"
            )
            findings_html = self._render_findings_list(
                r.get("threat_findings", [])
            )
            rows.append(f"""
            <tr>
                <td>
                    <span class="commit-sha">
                        <a href="{link}" target="_blank">
                            {escape(sha)}</a>
                    </span>
                    <div class="file-path">{escape(fpath)}</div>
                </td>
                <td>{findings_html}</td>
                <td>{r.get('threat_risk_delta', 0)}</td>
            </tr>""")

        return f"""
    <table>
        <thead>
            <tr>
                <th style="width:30%">Commit / File</th>
                <th>Threat Model Findings</th>
                <th style="width:10%">Risk Delta</th>
            </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
    </table>"""

    def _render_detail_row(
        self, index: int, result: Dict
    ) -> str:
        """Build one <tr> for the detail table."""
        sha = result.get("commit_sha", "")
        sha_short = sha[:8] if sha else "unknown"
        fpath = result.get("file_path", "")
        link = f"{self.repo_url}/commit/{sha}" if sha else "#"
        msg = result.get("commit_message", "")[:120]

        # Micro View column
        ck_delta = result.get("checkov_delta", 0)
        ck_after = result.get("checkov_findings_after", [])
        micro_html = self._render_checkov_cell(ck_delta, ck_after)

        # Macro View column
        threat_findings = result.get("threat_findings", [])
        risk_delta = result.get("threat_risk_delta", 0)
        macro_html = self._render_threat_cell(
            threat_findings, risk_delta,
            result.get("labels_before", []),
            result.get("labels_after", []),
        )

        # Attack class
        ac = result.get("attack_class", "")
        ac_name = self.ac_names.get(ac, ac)
        ac_html = (
            f"{escape(ac)}<br>"
            f"<span style='font-size:10px;color:#666'>"
            f"{escape(ac_name)}</span>"
            if ac else '<span class="empty">-</span>'
        )

        # Composite score
        score = result.get("composite_score", 0.0)
        bar_w = int(score * 100)
        score_html = (
            f"<strong>{score:.2f}</strong><br>"
            f'<span class="score-bar" style="width:{bar_w}px"></span>'
        )

        # Direction badge
        direction = result.get("posture_direction", "neutral")
        dir_class = f"badge-{direction}"
        dir_html = f'<span class="badge {dir_class}">{direction}</span>'

        # Flags
        flags = []
        if result.get("is_csi"):
            flags.append('<span class="badge badge-csi">CSI</span>')
        if result.get("macro_only"):
            flags.append('<span class="badge badge-macro">MACRO</span>')
        if result.get("micro_only"):
            flags.append('<span class="badge badge-micro">MICRO</span>')
        flags_html = " ".join(flags) if flags else "-"

        return f"""
            <tr>
                <td>
                    <span class="commit-sha">
                        <a href="{link}" target="_blank">
                            {escape(sha_short)}</a>
                    </span>
                    <div class="commit-msg">{escape(msg)}</div>
                    <div class="file-path">{escape(fpath)}</div>
                </td>
                <td>{micro_html}</td>
                <td>{macro_html}</td>
                <td>{ac_html}</td>
                <td>{score_html}</td>
                <td>{dir_html}</td>
                <td>{flags_html}</td>
            </tr>"""

    # -----------------------------------------------------------------
    # Cell renderers
    # -----------------------------------------------------------------
    def _render_checkov_cell(
        self, delta: int, findings: List[Dict]
    ) -> str:
        """Render the Micro View (Checkov) cell content."""
        if not findings and delta == 0:
            return '<span class="empty">No findings</span>'

        delta_class = "badge-regression" if delta > 0 else (
            "badge-improvement" if delta < 0 else "badge-neutral"
        )
        delta_sign = "+" if delta > 0 else ""
        parts = [
            f'<span class="badge {delta_class}">'
            f"delta: {delta_sign}{delta}</span>"
        ]

        for f in findings[:5]:
            sev = f.get("severity", "MEDIUM")
            rule = f.get("rule_id", "")
            title = f.get("title", "")[:60]
            parts.append(
                f'<div class="finding">'
                f'<span class="badge badge-severity sev-{sev}">'
                f"{sev}</span> "
                f"<strong>{escape(rule)}</strong> "
                f"{escape(title)}</div>"
            )
        if len(findings) > 5:
            parts.append(
                f'<div class="finding empty">'
                f"... and {len(findings) - 5} more</div>"
            )

        return "\n".join(parts)

    def _render_threat_cell(
        self,
        findings: List[Dict],
        risk_delta: int,
        labels_before: List[str],
        labels_after: List[str],
    ) -> str:
        """Render the Macro View (Threat Model) cell content."""
        if not findings and risk_delta == 0:
            return '<span class="empty">No findings</span>'

        parts = []
        if risk_delta != 0:
            rd_class = "badge-regression" if risk_delta > 0 else (
                "badge-improvement"
            )
            rd_sign = "+" if risk_delta > 0 else ""
            parts.append(
                f'<span class="badge {rd_class}">'
                f"risk: {rd_sign}{risk_delta}</span>"
            )

        for f in findings[:5]:
            ct = f.get("change_type", "")
            elem = f.get("element_name", "")[:30]
            ac = f.get("attack_class", "")
            sev = f.get("severity", "MEDIUM")
            parts.append(
                f'<div class="finding">'
                f'<span class="badge badge-severity sev-{sev}">'
                f"{sev}</span> "
                f"<strong>{escape(ct)}</strong> "
                f"{escape(elem)}"
                f"{' [' + escape(ac) + ']' if ac else ''}"
                f"</div>"
            )
        if len(findings) > 5:
            parts.append(
                f'<div class="finding empty">'
                f"... and {len(findings) - 5} more</div>"
            )

        return "\n".join(parts)

    @staticmethod
    def _render_findings_list(findings: List[Dict]) -> str:
        """Render a compact list of threat findings."""
        if not findings:
            return '<span class="empty">-</span>'

        parts = []
        for f in findings[:8]:
            ct = f.get("change_type", "")
            elem = f.get("element_name", "")[:30]
            ac = f.get("attack_class", "")
            sev = f.get("severity", "")
            parts.append(
                f'<div class="finding">'
                f'<span class="badge badge-severity sev-{sev}">'
                f"{sev}</span> "
                f"{escape(ct)} "
                f"<strong>{escape(elem)}</strong>"
                f"{' [' + escape(ac) + ']' if ac else ''}"
                f"</div>"
            )
        return "\n".join(parts)
