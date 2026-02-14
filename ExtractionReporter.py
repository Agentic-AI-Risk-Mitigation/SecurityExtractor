"""
ExtractionReporter.py - HTML Table Report for Security Deltas
==============================================================

Creates a clean HTML table for manual inspection of security-relevant
git commits. Accepts data either from a JSONL file or directly from
an in-memory list (e.g. passed by PipelineRunner.py).

Usage (from file):
    reporter = ExtractionReporter("report.html", "https://github.com/org/repo")
    reporter.generate(jsonl_file="deltas.jsonl")

Usage (from memory):
    reporter = ExtractionReporter("report.html", "https://github.com/org/repo")
    reporter.generate(deltas=results)
"""

import json
from html import escape
from datetime import datetime
from typing import List, Dict, Optional


class ExtractionReporter:
    """Generates a simple HTML table report from security delta data."""

    def __init__(self, output_file: str, repo_url: str):
        """
        Parameters
        ----------
        output_file : str
            Path where the HTML report will be written.
        repo_url : str
            Base GitHub/GitLab URL used to build commit links.
        """
        self.output_file = output_file
        self.repo_url = repo_url

    @staticmethod
    def _load_jsonl(jsonl_file: str) -> List[Dict]:
        """Load entries from a JSONL file."""
        deltas = []
        with open(jsonl_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    deltas.append(json.loads(line))
        return deltas

    @staticmethod
    def _parse_before_after(diff_text: str):
        """Split a unified diff into removed / added line lists."""
        before_lines, after_lines = [], []
        if not diff_text:
            return before_lines, after_lines
        for line in diff_text.split("\n"):
            if line.startswith("-") and not line.startswith("---"):
                before_lines.append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                after_lines.append(line[1:])
        return before_lines, after_lines

    @staticmethod
    def _format_diff_html(diff_text: str) -> str:
        """Render a unified diff with colour-coded line spans."""
        if not diff_text:
            return '<span class="empty">(no diff available)</span>'
        parts = []
        for line in diff_text.split("\n"):
            escaped = escape(line)
            if line.startswith("@@"):
                parts.append(f'<span class="line-header">{escaped}</span>')
            elif line.startswith("-") and not line.startswith("---"):
                parts.append(f'<span class="line-removed">{escaped}</span>')
            elif line.startswith("+") and not line.startswith("+++"):
                parts.append(f'<span class="line-added">{escaped}</span>')
            elif line.startswith("---") or line.startswith("+++"):
                continue
            else:
                parts.append(f'<span class="line-context">{escaped}</span>')
        return "\n".join(parts) if parts else '<span class="empty">(no diff available)</span>'

    def _render_row(self, index: int, delta: Dict) -> str:
        """Build the HTML for one <tr>."""
        commit_sha = delta.get("commit_sha", delta.get("sha", ""))
        sha_short = commit_sha[:7] if commit_sha else "unknown"
        commit_msg = delta.get("commit_message", "")
        file_path = delta.get("file", "unknown")
        diff_text = delta.get("diff", "")
        commit_link = f"{self.repo_url}/commit/{commit_sha}" if commit_sha else "#"

        before_lines, after_lines = self._parse_before_after(diff_text)
        before_html = (
            escape("\n".join(before_lines))
            if before_lines
            else '<span class="empty">(no lines removed)</span>'
        )
        after_html = (
            escape("\n".join(after_lines))
            if after_lines
            else '<span class="empty">(no lines added)</span>'
        )
        diff_html = self._format_diff_html(diff_text)

        matched = delta.get("keywords_matched", [])
        keywords_html = (
            "".join(f'<span class="keyword">{escape(kw)}</span>' for kw in matched)
            if matched
            else '<span class="empty">-</span>'
        )

        return f"""
            <tr>
                <td class="col-commit">
                    <span class="row-num">#{index}</span>
                    <span class="commit-sha"><a href="{commit_link}" target="_blank">{escape(sha_short)}</a></span>
                    <div class="commit-msg">{escape(commit_msg[:200])}</div>
                    <div class="file-path">{escape(file_path)}</div>
                </td>
                <td class="col-before">
                    <div class="line-count removed">▼ {len(before_lines)} lines removed</div>
                    <pre class="before-code">{before_html}</pre>
                </td>
                <td class="col-after">
                    <div class="line-count added">▲ {len(after_lines)} lines added</div>
                    <pre class="after-code">{after_html}</pre>
                </td>
                <td class="col-diff">
                    <pre class="diff-code">{diff_html}</pre>
                </td>
                <td class="col-keywords">
                    {keywords_html}
                </td>
            </tr>"""

    def _build_html(self, deltas: List[Dict], source_label: str) -> str:
        """Assemble the complete HTML document."""
        rows = "\n".join(
            self._render_row(i, delta) for i, delta in enumerate(deltas, 1)
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Deltas - Simple Table View</title>
    <style>
        * {{ box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            margin: 0;
            padding: 20px;
            background: #fafafa;
            font-size: 13px;
            line-height: 1.4;
        }}

        h1 {{
            font-size: 20px;
            margin-bottom: 5px;
            color: #333;
        }}

        .subtitle {{
            color: #666;
            margin-bottom: 20px;
            font-size: 12px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            table-layout: fixed;
        }}

        th {{
            background: #2c3e50;
            color: white;
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            position: sticky;
            top: 0;
            z-index: 10;
        }}

        td {{
            padding: 10px 8px;
            border: 1px solid #ddd;
            vertical-align: top;
        }}

        tr:nth-child(even) {{
            background: #f9f9f9;
        }}

        tr:hover {{
            background: #fff3cd;
        }}

        .col-commit {{ width: 18%; }}
        .col-before {{ width: 24%; background: #fff5f5; color: #000000; }}
        .col-after {{ width: 24%; background: #f5fff5; color: #000000; }}
        .col-diff {{ width: 24%; }}
        .col-keywords {{ width: 10%; }}

        .commit-sha {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 11px;
            background: #e3f2fd;
            padding: 2px 6px;
            border-radius: 3px;
            display: inline-block;
            margin-bottom: 4px;
        }}

        .commit-sha a {{
            color: #1565c0;
            text-decoration: none;
        }}

        .commit-sha a:hover {{
            text-decoration: underline;
        }}

        .commit-msg {{
            font-size: 11px;
            color: #333;
            margin: 4px 0;
            word-wrap: break-word;
        }}

        .file-path {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 10px;
            color: #666;
            word-break: break-all;
            background: #f5f5f5;
            padding: 2px 4px;
            border-radius: 2px;
        }}

        pre {{
            margin: 0;
            padding: 8px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 10px;
            white-space: pre-wrap;
            word-wrap: break-word;
            background: #f8f8f8;
            border-radius: 4px;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #e0e0e0;
        }}

        .before-code {{
            background: #ffebee;
            border-color: #ffcdd2;
        }}

        .after-code {{
            background: #e8f5e9;
            border-color: #c8e6c9;
        }}

        .diff-code {{
            background: #fafafa;
        }}

        .line-removed {{
            background: #ffcdd2;
            display: block;
            margin: 0 -8px;
            padding: 0 8px;
        }}

        .line-added {{
            background: #c8e6c9;
            display: block;
            margin: 0 -8px;
            padding: 0 8px;
        }}

        .line-context {{
            color: #666;
        }}

        .line-header {{
            color: #1565c0;
            font-weight: bold;
            background: #e3f2fd;
            display: block;
            margin: 0 -8px;
            padding: 0 8px;
        }}

        .keyword {{
            display: inline-block;
            background: #fff3e0;
            color: #e65100;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            margin: 2px;
            font-weight: 500;
        }}

        .row-num {{
            font-size: 10px;
            color: #999;
            display: block;
            margin-bottom: 4px;
        }}

        .empty {{
            color: #999;
            font-style: italic;
            font-size: 11px;
        }}

        footer {{
            margin-top: 20px;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 6px;
            font-size: 11px;
            color: #666;
        }}

        .line-count {{
            font-size: 10px;
            color: #666;
            margin-bottom: 4px;
        }}

        .line-count.removed {{ color: #c62828; }}
        .line-count.added {{ color: #2e7d32; }}
    </style>
</head>
<body>
    <h1>Security Deltas Report</h1>
    <p class="subtitle">
        {len(deltas)} entries analyzed |
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} |
        Source: {escape(source_label)}
    </p>

    <table>
        <thead>
            <tr>
                <th class="col-commit">Commit / File</th>
                <th class="col-before">BEFORE (Removed Lines)</th>
                <th class="col-after">AFTER (Added Lines)</th>
                <th class="col-diff">DIFF (Full Patch)</th>
                <th class="col-keywords">Keywords</th>
            </tr>
        </thead>
        <tbody>
{rows}
        </tbody>
    </table>

    <footer>
        <strong>How to use this report:</strong><br>
        • <strong>BEFORE</strong> column shows lines that were removed (potential vulnerable code)<br>
        • <strong>AFTER</strong> column shows lines that were added (potential fixes)<br>
        • <strong>DIFF</strong> column shows the full patch with context<br>
        • Click commit SHA to view the full commit on GitHub<br>
        • Keywords are read from the extractor output
    </footer>
</body>
</html>
"""

    def generate(
        self,
        deltas: Optional[List[Dict]] = None,
        jsonl_file: Optional[str] = None,
    ) -> str:
        """
        Build the HTML report and write it to disk.

        Provide exactly one of:
            deltas     — in-memory list of dicts (e.g. from PipelineRunner.py)
            jsonl_file — path to a JSONL file on disk

        Returns the output file path.
        """
        if deltas is not None and jsonl_file is not None:
            raise ValueError("Provide either 'deltas' or 'jsonl_file', not both.")
        if deltas is None and jsonl_file is None:
            raise ValueError("Provide either 'deltas' or 'jsonl_file'.")

        if jsonl_file is not None:
            deltas = self._load_jsonl(jsonl_file)
            source_label = jsonl_file
        else:
            source_label = "in-memory data"

        html = self._build_html(deltas, source_label)

        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"Saved HTML report to {self.output_file}")
        print(f"Total entries: {len(deltas)}")

        return self.output_file

