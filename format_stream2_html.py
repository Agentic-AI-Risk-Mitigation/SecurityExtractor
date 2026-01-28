#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
format_stream2_html.py - HTML Formatter for Stream 2 Research
==============================================================

Creates a simple tabular HTML output optimized for Stream 2 research:
- Security posture analysis (restrictive → permissive)
- Before/After/Delta comparison
- All relevant metadata for training datasets

Usage:
    from format_stream2_html import format_security_deltas_html
    format_security_deltas_html("security_deltas.jsonl", "report.html")
"""

import json
import re
from html import escape
from datetime import datetime
from typing import List, Dict

# =============================================================================
# SECURITY POSTURE PATTERNS (for Stream 2 analysis)
# =============================================================================

# Patterns indicating PERMISSIVE (less secure) configurations
PERMISSIVE_PATTERNS = [
    # Kubernetes
    (r'privileged:\s*true', 'K8S: Privileged container', 'CRITICAL'),
    (r'runAsUser:\s*0\b', 'K8S: Running as root', 'HIGH'),
    (r'allowPrivilegeEscalation:\s*true', 'K8S: Privilege escalation allowed', 'HIGH'),
    (r'hostNetwork:\s*true', 'K8S: Host network access', 'HIGH'),
    (r'hostPID:\s*true', 'K8S: Host PID access', 'HIGH'),
    (r'hostIPC:\s*true', 'K8S: Host IPC access', 'MEDIUM'),
    (r'readOnlyRootFilesystem:\s*false', 'K8S: Writable root filesystem', 'MEDIUM'),
    (r'runAsNonRoot:\s*false', 'K8S: Can run as root', 'HIGH'),

    # Secrets/Credentials
    (r'password\s*[:=]\s*["\'][^${\s]', 'Hardcoded password', 'CRITICAL'),
    (r'(api_key|apikey|secret_key)\s*[:=]\s*["\']', 'Hardcoded secret', 'CRITICAL'),

    # Network
    (r'0\.0\.0\.0', 'Binding to all interfaces', 'MEDIUM'),
    (r'cidr.*0\.0\.0\.0/0', 'Open CIDR (internet)', 'CRITICAL'),

    # Terraform
    (r'publicly_accessible\s*=\s*true', 'TF: Publicly accessible', 'HIGH'),
    (r'encrypted\s*=\s*false', 'TF: Encryption disabled', 'HIGH'),
]

# Patterns indicating RESTRICTIVE (more secure) configurations
RESTRICTIVE_PATTERNS = [
    # Kubernetes
    (r'privileged:\s*false', 'K8S: Non-privileged', 'SECURE'),
    (r'runAsNonRoot:\s*true', 'K8S: Must run as non-root', 'SECURE'),
    (r'allowPrivilegeEscalation:\s*false', 'K8S: Escalation blocked', 'SECURE'),
    (r'readOnlyRootFilesystem:\s*true', 'K8S: Read-only filesystem', 'SECURE'),
    (r'drop:\s*\n\s*-\s*ALL', 'K8S: All capabilities dropped', 'SECURE'),

    # Terraform
    (r'encrypted\s*=\s*true', 'TF: Encryption enabled', 'SECURE'),
    (r'publicly_accessible\s*=\s*false', 'TF: Not publicly accessible', 'SECURE'),
]


def analyze_security_posture(content: str) -> Dict:
    """
    Analyze content for security posture indicators.
    Returns counts and details of permissive/restrictive patterns.
    """
    permissive_findings = []
    restrictive_findings = []

    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        for pattern, desc, severity in PERMISSIVE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                permissive_findings.append({
                    'line': i,
                    'description': desc,
                    'severity': severity,
                    'content': line.strip()[:80]
                })

        for pattern, desc, _ in RESTRICTIVE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                restrictive_findings.append({
                    'line': i,
                    'description': desc,
                    'content': line.strip()[:80]
                })

    # Calculate risk score
    severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
    risk_score = sum(severity_weights.get(f['severity'], 1) for f in permissive_findings)

    return {
        'permissive': permissive_findings,
        'restrictive': restrictive_findings,
        'permissive_count': len(permissive_findings),
        'restrictive_count': len(restrictive_findings),
        'risk_score': risk_score
    }


def compute_delta(before_analysis: Dict, after_analysis: Dict) -> Dict:
    """
    Compute the security posture delta between before and after states.
    This is key for Stream 2: detecting restrictive → permissive changes.
    """
    before_risk = before_analysis['risk_score']
    after_risk = after_analysis['risk_score']
    risk_delta = after_risk - before_risk

    # Determine posture change direction
    if risk_delta > 0:
        direction = 'REGRESSION'  # Security weakened (restrictive → permissive)
        direction_icon = '⚠️'
        direction_class = 'regression'
    elif risk_delta < 0:
        direction = 'IMPROVEMENT'  # Security strengthened (permissive → restrictive)
        direction_icon = '✅'
        direction_class = 'improvement'
    else:
        direction = 'NEUTRAL'
        direction_icon = '➖'
        direction_class = 'neutral'

    return {
        'before_risk': before_risk,
        'after_risk': after_risk,
        'risk_delta': risk_delta,
        'direction': direction,
        'direction_icon': direction_icon,
        'direction_class': direction_class,
        'before_permissive': before_analysis['permissive_count'],
        'after_permissive': after_analysis['permissive_count'],
        'before_restrictive': before_analysis['restrictive_count'],
        'after_restrictive': after_analysis['restrictive_count'],
    }


def extract_diff_lines(diff_text: str) -> Dict:
    """Extract added and removed lines from diff."""
    removed = []
    added = []

    if not diff_text:
        return {'removed': [], 'added': []}

    for line in diff_text.split('\n'):
        if line.startswith('-') and not line.startswith('---'):
            removed.append(line[1:])
        elif line.startswith('+') and not line.startswith('+++'):
            added.append(line[1:])

    return {'removed': removed, 'added': added}


def format_security_deltas_html(
        jsonl_file: str = "security_deltas.jsonl",
        output_file: str = "stream2_security_report.html"
) -> str:
    """
    Generate HTML report optimized for Stream 2 research.

    Table columns:
    - Commit metadata (SHA, date, author, message)
    - File information
    - BEFORE state analysis
    - AFTER state analysis
    - DELTA (security posture change)
    - Keywords matched
    """

    # Load data
    deltas = []
    with open(jsonl_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                deltas.append(json.loads(line))

    # Analyze each delta
    analyzed_deltas = []
    for delta in deltas:
        before_analysis = analyze_security_posture(delta.get('before', ''))
        after_analysis = analyze_security_posture(delta.get('after', ''))
        posture_delta = compute_delta(before_analysis, after_analysis)
        diff_lines = extract_diff_lines(delta.get('diff', ''))

        analyzed_deltas.append({
            **delta,
            'before_analysis': before_analysis,
            'after_analysis': after_analysis,
            'posture_delta': posture_delta,
            'diff_lines': diff_lines,
        })

    # Calculate summary statistics
    total = len(analyzed_deltas)
    regressions = sum(1 for d in analyzed_deltas if d['posture_delta']['direction'] == 'REGRESSION')
    improvements = sum(1 for d in analyzed_deltas if d['posture_delta']['direction'] == 'IMPROVEMENT')
    neutral = total - regressions - improvements

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stream 2: Security Posture Analysis</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            font-size: 14px;
        }}

        h1 {{ color: #333; margin-bottom: 10px; }}

        .summary {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary h2 {{ margin-top: 0; font-size: 16px; }}
        .stats {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        .stat {{
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: bold;
        }}
        .stat.total {{ background: #e3f2fd; color: #1565c0; }}
        .stat.regression {{ background: #ffebee; color: #c62828; }}
        .stat.improvement {{ background: #e8f5e9; color: #2e7d32; }}
        .stat.neutral {{ background: #fff3e0; color: #ef6c00; }}

        /* Main Table */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .data-table th {{
            background: #1565c0;
            color: white;
            padding: 12px 8px;
            text-align: left;
            font-size: 12px;
            position: sticky;
            top: 0;
        }}
        .data-table td {{
            padding: 10px 8px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }}
        .data-table tr:hover {{
            background: #f5f5f5;
        }}

        /* Column styles */
        .col-meta {{ width: 20%; }}
        .col-before {{ width: 25%; background: #fff8f8; }}
        .col-after {{ width: 25%; background: #f8fff8; }}
        .col-delta {{ width: 15%; }}
        .col-keywords {{ width: 15%; }}

        /* Cell content */
        .commit-sha {{
            font-family: monospace;
            font-size: 11px;
            color: #1565c0;
        }}
        .commit-msg {{
            font-size: 12px;
            color: #666;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .file-path {{
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
        }}
        .date {{ font-size: 11px; color: #999; }}
        .author {{ font-size: 11px; color: #666; }}

        /* Code blocks */
        pre {{
            background: #f8f8f8;
            padding: 8px;
            border-radius: 4px;
            font-size: 10px;
            overflow-x: auto;
            max-height: 150px;
            overflow-y: auto;
            margin: 5px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .before-code {{ background: #ffebee; }}
        .after-code {{ background: #e8f5e9; }}

        /* Security indicators */
        .risk-score {{
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
            display: inline-block;
            margin: 2px 0;
        }}
        .risk-high {{ background: #ffcdd2; color: #b71c1c; }}
        .risk-medium {{ background: #fff3e0; color: #e65100; }}
        .risk-low {{ background: #e8f5e9; color: #2e7d32; }}

        /* Delta indicators */
        .delta-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            display: inline-block;
        }}
        .delta-regression {{ background: #ffcdd2; color: #b71c1c; }}
        .delta-improvement {{ background: #c8e6c9; color: #1b5e20; }}
        .delta-neutral {{ background: #fff3e0; color: #e65100; }}

        .delta-value {{
            font-size: 18px;
            font-weight: bold;
        }}
        .delta-positive {{ color: #c62828; }}
        .delta-negative {{ color: #2e7d32; }}
        .delta-zero {{ color: #757575; }}

        /* Keywords */
        .keyword {{
            display: inline-block;
            background: #e3f2fd;
            color: #1565c0;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            margin: 1px;
        }}

        /* Findings list */
        .findings {{
            font-size: 11px;
            margin: 5px 0;
        }}
        .finding {{
            padding: 2px 0;
            border-bottom: 1px dotted #ddd;
        }}
        .finding:last-child {{ border-bottom: none; }}
        .severity-critical {{ color: #b71c1c; font-weight: bold; }}
        .severity-high {{ color: #e65100; }}
        .severity-medium {{ color: #f9a825; }}

        /* Expandable rows */
        .expand-btn {{
            cursor: pointer;
            color: #1565c0;
            font-size: 11px;
        }}
        .detail-row {{ display: none; }}
        .detail-row.visible {{ display: table-row; }}
        .detail-cell {{
            padding: 15px;
            background: #fafafa;
        }}

        /* Search/Filter */
        .controls {{
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .search-box {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 300px;
        }}
        .filter-btn {{
            padding: 8px 16px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
            cursor: pointer;
        }}
        .filter-btn:hover {{ background: #f5f5f5; }}
        .filter-btn.active {{ background: #1565c0; color: white; border-color: #1565c0; }}
    </style>
</head>
<body>
    <h1>🔒 Stream 2: Security Posture Delta Analysis</h1>
    <p>Detecting security posture changes (restrictive → permissive) in IaC commits</p>

    <div class="summary">
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat total">Total: {total}</div>
            <div class="stat regression">⚠️ Regressions: {regressions}</div>
            <div class="stat improvement">✅ Improvements: {improvements}</div>
            <div class="stat neutral">➖ Neutral: {neutral}</div>
        </div>
    </div>

    <div class="controls">
        <input type="text" class="search-box" id="searchBox" placeholder="Search commits, files, keywords...">
        <button class="filter-btn" onclick="filterBy('')">All</button>
        <button class="filter-btn" onclick="filterBy('REGRESSION')">⚠️ Regressions Only</button>
        <button class="filter-btn" onclick="filterBy('IMPROVEMENT')">✅ Improvements Only</button>
    </div>

    <table class="data-table" id="dataTable">
        <thead>
            <tr>
                <th class="col-meta">Commit / File</th>
                <th class="col-before">BEFORE State</th>
                <th class="col-after">AFTER State</th>
                <th class="col-delta">DELTA (Posture Change)</th>
                <th class="col-keywords">Keywords</th>
            </tr>
        </thead>
        <tbody>
"""

    for i, delta in enumerate(analyzed_deltas, 1):
        # Extract data
        sha = delta.get('commit_sha', delta.get('sha', ''))[:7]
        msg = escape(delta.get('commit_message', '')[:60])
        file_path = escape(delta.get('file', 'unknown'))
        date = delta.get('commit_date', delta.get('date', ''))[:10]
        author = escape(delta.get('author', 'unknown'))
        keywords = delta.get('keywords_matched', [])

        before_analysis = delta['before_analysis']
        after_analysis = delta['after_analysis']
        posture = delta['posture_delta']
        diff_lines = delta['diff_lines']

        # Risk score classes
        before_risk_class = 'risk-high' if before_analysis['risk_score'] > 10 else (
            'risk-medium' if before_analysis['risk_score'] > 0 else 'risk-low')
        after_risk_class = 'risk-high' if after_analysis['risk_score'] > 10 else (
            'risk-medium' if after_analysis['risk_score'] > 0 else 'risk-low')

        # Delta class
        delta_class = f"delta-{posture['direction_class']}"
        delta_value_class = 'delta-positive' if posture['risk_delta'] > 0 else (
            'delta-negative' if posture['risk_delta'] < 0 else 'delta-zero')

        # Format before findings
        before_findings_html = ""
        for f in before_analysis['permissive'][:3]:
            sev_class = f"severity-{f['severity'].lower()}"
            before_findings_html += f'<div class="finding"><span class="{sev_class}">[{f["severity"]}]</span> {escape(f["description"])}</div>'

        # Format after findings
        after_findings_html = ""
        for f in after_analysis['permissive'][:3]:
            sev_class = f"severity-{f['severity'].lower()}"
            after_findings_html += f'<div class="finding"><span class="{sev_class}">[{f["severity"]}]</span> {escape(f["description"])}</div>'

        # Format diff preview
        removed_preview = '\\n'.join(escape(l.strip())[:50] for l in diff_lines['removed'][:3])
        added_preview = '\\n'.join(escape(l.strip())[:50] for l in diff_lines['added'][:3])

        # Keywords HTML
        keywords_html = ''.join(f'<span class="keyword">{escape(kw)}</span>' for kw in keywords[:5])

        html += f"""
            <tr data-direction="{posture['direction']}" data-search="{escape((msg + ' ' + file_path + ' ' + ' '.join(keywords)).lower())}">
                <td class="col-meta">
                    <div class="commit-sha">#{i} {sha}</div>
                    <div class="file-path">{file_path}</div>
                    <div class="commit-msg" title="{msg}">{msg}</div>
                    <div class="date">{date}</div>
                    <div class="author">{author}</div>
                </td>
                <td class="col-before">
                    <div class="risk-score {before_risk_class}">Risk: {before_analysis['risk_score']}</div>
                    <div>Permissive: {before_analysis['permissive_count']} | Restrictive: {before_analysis['restrictive_count']}</div>
                    <div class="findings">{before_findings_html or '<em>No issues detected</em>'}</div>
                    <pre class="before-code">{removed_preview or '(no lines removed)'}</pre>
                </td>
                <td class="col-after">
                    <div class="risk-score {after_risk_class}">Risk: {after_analysis['risk_score']}</div>
                    <div>Permissive: {after_analysis['permissive_count']} | Restrictive: {after_analysis['restrictive_count']}</div>
                    <div class="findings">{after_findings_html or '<em>No issues detected</em>'}</div>
                    <pre class="after-code">{added_preview or '(no lines added)'}</pre>
                </td>
                <td class="col-delta">
                    <div class="delta-badge {delta_class}">{posture['direction_icon']} {posture['direction']}</div>
                    <div class="delta-value {delta_value_class}">
                        {'+' if posture['risk_delta'] > 0 else ''}{posture['risk_delta']}
                    </div>
                    <div style="font-size:11px;">
                        Risk: {posture['before_risk']} → {posture['after_risk']}
                    </div>
                </td>
                <td class="col-keywords">
                    {keywords_html or '<em>none</em>'}
                </td>
            </tr>
"""

    html += """
        </tbody>
    </table>

    <script>
        // Search functionality
        document.getElementById('searchBox').addEventListener('input', function() {
            const query = this.value.toLowerCase();
            const rows = document.querySelectorAll('#dataTable tbody tr');
            rows.forEach(row => {
                const searchData = row.getAttribute('data-search') || '';
                row.style.display = searchData.includes(query) ? '' : 'none';
            });
        });

        // Filter by direction
        function filterBy(direction) {
            const rows = document.querySelectorAll('#dataTable tbody tr');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            rows.forEach(row => {
                if (!direction || row.getAttribute('data-direction') === direction) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    </script>

    <div style="margin-top: 20px; padding: 15px; background: #e3f2fd; border-radius: 8px;">
        <h3 style="margin-top: 0;">Stream 2 Research Notes</h3>
        <p><strong>Key Metrics for Analysis:</strong></p>
        <ul>
            <li><strong>Risk Score:</strong> Weighted sum of permissive patterns (CRITICAL=10, HIGH=5, MEDIUM=2)</li>
            <li><strong>Delta:</strong> Positive = security weakened (regression), Negative = security improved</li>
            <li><strong>Direction:</strong> REGRESSION indicates restrictive→permissive posture change</li>
        </ul>
        <p><strong>Patterns Detected:</strong> Privileged containers, root users, host access, hardcoded secrets, open CIDRs, disabled encryption</p>
    </div>

    <footer style="text-align: center; padding: 20px; color: #666; font-size: 12px;">
        Generated: """ + datetime.now().isoformat() + f"""<br>
        Total entries: {total} | Data source: {jsonl_file}
    </footer>
</body>
</html>
"""

    # Save to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Saved Stream 2 HTML report to {output_file}")
    print(f"   Total: {total} | Regressions: {regressions} | Improvements: {improvements}")

    return output_file


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Direct configuration - edit these values
    INPUT_FILE = "security_deltas.jsonl"
    OUTPUT_FILE = "stream2_security_report.html"

    format_security_deltas_html(INPUT_FILE, OUTPUT_FILE)