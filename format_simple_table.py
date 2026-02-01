#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
format_simple_table.py - Simple HTML Table Formatter for Security Deltas
=========================================================================

Creates a clean, simple HTML table for manual inspection of security-relevant
git commits. No fancy interactivity - just clear, readable data.

Columns:
1. Commit Info (SHA with link, message, file path)
2. Before (removed lines from diff)
3. After (added lines from diff)
4. Diff (full patch)
5. Matched Keywords

Usage:
    python format_simple_table.py security_deltas.jsonl output.html

Or import:
    from format_simple_table import format_simple_html_table
    format_simple_html_table("security_deltas.jsonl", "output.html")
"""

import json
import sys
from html import escape
from datetime import datetime


def extract_keywords_from_message(message: str, keywords: list) -> list:
    """Extract which keywords were matched in the commit message."""
    msg_lower = message.lower()
    return [kw for kw in keywords if kw.lower() in msg_lower]


def format_simple_html_table(
        jsonl_file: str = "security_deltas.jsonl",
        output_file: str = "security_deltas_simple.html",
        repo_url: str = "https://github.com/kubernetes/kubernetes",
        keywords: list = None
) -> str:
    """
    Generate a simple HTML table for manual inspection of security deltas.

    Args:
        jsonl_file: Input JSONL file with security delta data
        output_file: Output HTML file path
        repo_url: Base URL for commit links
        keywords: List of keywords to highlight (uses default if not provided)

    Returns:
        Path to the generated HTML file
    """

    if keywords is None:
        keywords = ["security", "fix", "vuln", "rbac", "secret", "privileged",
                    "cve", "auth", "permission", "access", "overflow"]

    # Load data
    deltas = []
    with open(jsonl_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                deltas.append(json.loads(line))

    # Build HTML
    html = f"""<!DOCTYPE html>
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

        /* Simple Table Styles */
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

        /* Column widths */
        .col-commit {{ width: 18%; }}
        .col-before {{ width: 24%; background: #fff5f5; color: #000000; }}
        .col-after {{ width: 24%; background: #f5fff5; color: #000000; }}
        .col-diff {{ width: 24%; }}
        .col-keywords {{ width: 10%; }}

        /* Commit info styling */
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

        /* Code blocks */
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

        /* Line highlighting in diff */
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

        /* Keywords */
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

        /* Row number */
        .row-num {{
            font-size: 10px;
            color: #999;
            display: block;
            margin-bottom: 4px;
        }}

        /* Empty state */
        .empty {{
            color: #999;
            font-style: italic;
            font-size: 11px;
        }}

        /* Footer */
        footer {{
            margin-top: 20px;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 6px;
            font-size: 11px;
            color: #666;
        }}

        /* Line count badge */
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
    <h1>🔒 Security Deltas Report</h1>
    <p class="subtitle">
        {len(deltas)} commits analyzed | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | 
        Source: {escape(jsonl_file)}
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
"""

    for i, delta in enumerate(deltas, 1):
        # Extract data
        commit_sha = delta.get('commit_sha', delta.get('sha', ''))
        sha_short = commit_sha[:7] if commit_sha else 'unknown'
        commit_msg = delta.get('commit_message', '')
        file_path = delta.get('file', 'unknown')
        diff_text = delta.get('diff', '')

        # Build commit link
        if commit_sha:
            commit_link = f'{repo_url}/commit/{commit_sha}'
        else:
            commit_link = '#'

        # Extract before/after lines from diff
        before_lines = []
        after_lines = []

        if diff_text:
            for line in diff_text.split('\n'):
                if line.startswith('-') and not line.startswith('---'):
                    before_lines.append(line[1:])  # Remove the leading '-'
                elif line.startswith('+') and not line.startswith('+++'):
                    after_lines.append(line[1:])  # Remove the leading '+'

        # Extract matched keywords
        matched_keywords = extract_keywords_from_message(commit_msg, keywords)

        # Format before code
        if before_lines:
            before_html = escape('\n'.join(before_lines))
        else:
            before_html = '<span class="empty">(no lines removed)</span>'

        # Format after code
        if after_lines:
            after_html = escape('\n'.join(after_lines))
        else:
            after_html = '<span class="empty">(no lines added)</span>'

        # Format diff with syntax highlighting
        diff_lines_html = []
        if diff_text:
            for line in diff_text.split('\n'):
                escaped_line = escape(line)
                if line.startswith('@@'):
                    diff_lines_html.append(f'<span class="line-header">{escaped_line}</span>')
                elif line.startswith('-') and not line.startswith('---'):
                    diff_lines_html.append(f'<span class="line-removed">{escaped_line}</span>')
                elif line.startswith('+') and not line.startswith('+++'):
                    diff_lines_html.append(f'<span class="line-added">{escaped_line}</span>')
                elif line.startswith('---') or line.startswith('+++'):
                    continue  # Skip file headers
                else:
                    diff_lines_html.append(f'<span class="line-context">{escaped_line}</span>')

        diff_html = '\n'.join(diff_lines_html) if diff_lines_html else '<span class="empty">(no diff available)</span>'

        # Format keywords
        if matched_keywords:
            keywords_html = ''.join(f'<span class="keyword">{escape(kw)}</span>' for kw in matched_keywords)
        else:
            keywords_html = '<span class="empty">-</span>'

        # Add row to table
        html += f"""
            <tr>
                <td class="col-commit">
                    <span class="row-num">#{i}</span>
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
            </tr>
"""

    html += """
        </tbody>
    </table>

    <footer>
        <strong>How to use this report:</strong><br>
        • <strong>BEFORE</strong> column shows lines that were removed (potential vulnerable code)<br>
        • <strong>AFTER</strong> column shows lines that were added (potential fixes)<br>
        • <strong>DIFF</strong> column shows the full patch with context<br>
        • Click commit SHA to view the full commit on GitHub<br>
        • Keywords are extracted from the commit message
    </footer>
</body>
</html>
"""

    # Save to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Saved simple HTML table to {output_file}")
    print(f"   Total entries: {len(deltas)}")

    return output_file


# =============================================================================
# Integration with extractor_simple.py
# =============================================================================

def format_deltas_simple_table(json_module, escape_func,
                               jsonl_file="security_deltas.jsonl",
                               output_file="security_deltas_simple.html",
                               repo_url="https://github.com/kubernetes/kubernetes"):
    """
    Drop-in replacement for format_deltas_html that creates a simple table.
    Compatible with the calling convention in extractor_simple.py
    """
    return format_simple_html_table(jsonl_file, output_file, repo_url)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Direct configuration - edit these values
    INPUT_FILE = "security_deltas.jsonl"
    OUTPUT_FILE = "stream2_security_report.html"

    format_simple_html_table(INPUT_FILE, OUTPUT_FILE)
