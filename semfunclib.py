#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
funclib.py - Security Delta Extraction Library
==============================================

Detection methods (in order of sophistication):
1. Keyword matching (simple, fast, low precision)
2. Semgrep rules (pattern-based, high precision for known issues)
3. NLP/BERT (future: semantic understanding, context-aware)

Install dependencies:
    pip install PyGithub python-dotenv semgrep

For NLP/BERT (future):
    pip install transformers torch sentence-transformers
"""

import os
import re
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from html import escape


# =============================================================================
# SEMGREP INTEGRATION
# =============================================================================

# Custom Semgrep rules for IaC security (Kubernetes, Docker, Terraform)
# These rules detect ACTUAL security misconfigurations, not just keywords
SEMGREP_RULES_YAML = """
rules:
  # ============== KUBERNETES RULES ==============
  
  - id: k8s-privileged-container
    patterns:
      - pattern: |
          privileged: true
    message: "Privileged container detected - allows full host access"
    severity: ERROR
    languages: [yaml]
    metadata:
      category: security
      cwe: "CWE-250"
      confidence: HIGH

  - id: k8s-run-as-root
    patterns:
      - pattern: |
          runAsUser: 0
    message: "Container running as root (UID 0)"
    severity: WARNING
    languages: [yaml]
    metadata:
      category: security
      cwe: "CWE-250"
      confidence: HIGH

  - id: k8s-privilege-escalation
    patterns:
      - pattern: |
          allowPrivilegeEscalation: true
    message: "Privilege escalation allowed"
    severity: ERROR
    languages: [yaml]
    metadata:
      category: security
      cwe: "CWE-269"
      confidence: HIGH

  - id: k8s-host-network
    patterns:
      - pattern: |
          hostNetwork: true
    message: "Pod has access to host network namespace"
    severity: WARNING
    languages: [yaml]
    metadata:
      category: security
      cwe: "CWE-668"
      confidence: HIGH

  - id: k8s-host-pid
    patterns:
      - pattern: |
          hostPID: true
    message: "Pod has access to host PID namespace"
    severity: WARNING
    languages: [yaml]
    metadata:
      category: security
      confidence: HIGH

  - id: k8s-writable-filesystem
    patterns:
      - pattern: |
          readOnlyRootFilesystem: false
    message: "Container has writable root filesystem"
    severity: INFO
    languages: [yaml]
    metadata:
      category: security
      confidence: MEDIUM

  - id: k8s-capabilities-all
    patterns:
      - pattern-inside: |
          capabilities:
            ...
      - pattern: |
          add:
            - ALL
    message: "All capabilities added to container"
    severity: ERROR
    languages: [yaml]
    metadata:
      category: security
      cwe: "CWE-250"
      confidence: HIGH

  - id: k8s-capabilities-sys-admin
    patterns:
      - pattern-inside: |
          capabilities:
            ...
      - pattern: |
          add:
            - SYS_ADMIN
    message: "SYS_ADMIN capability added (nearly equivalent to root)"
    severity: ERROR
    languages: [yaml]
    metadata:
      category: security
      cwe: "CWE-250"
      confidence: HIGH

  # ============== DOCKER RULES ==============

  - id: docker-run-as-root
    patterns:
      - pattern: |
          USER root
    message: "Dockerfile runs as root user"
    severity: WARNING
    languages: [dockerfile]
    metadata:
      category: security
      cwe: "CWE-250"
      confidence: HIGH

  - id: docker-expose-ssh
    patterns:
      - pattern: |
          EXPOSE 22
    message: "SSH port exposed in container"
    severity: INFO
    languages: [dockerfile]
    metadata:
      category: security
      confidence: MEDIUM

  - id: docker-add-from-url
    patterns:
      - pattern-regex: "ADD\\s+https?://"
    message: "ADD from URL - prefer COPY with verified files"
    severity: WARNING
    languages: [dockerfile]
    metadata:
      category: security
      cwe: "CWE-494"
      confidence: MEDIUM

  - id: docker-curl-pipe-bash
    patterns:
      - pattern-regex: "curl.*\\|.*sh"
    message: "Piping curl to shell - security risk"
    severity: ERROR
    languages: [dockerfile]
    metadata:
      category: security
      cwe: "CWE-494"
      confidence: HIGH
"""


class SemgrepAnalyzer:
    """
    Analyzes IaC files using Semgrep for precise security detection.
    
    Why Semgrep over keywords?
    ┌─────────────────────────────────────────────────────────────────┐
    │ Keywords: "privileged" in commit message                        │
    │   ❌ Catches: "removed privileged flag" (false positive)        │
    │   ❌ Catches: "documented privileged mode" (false positive)     │
    │   ✅ Catches: "added privileged: true" (true positive)          │
    │                                                                 │
    │ Semgrep: pattern "privileged: true" in YAML                     │
    │   ✅ Only catches actual privileged: true in code               │
    │   ✅ Understands YAML structure                                 │
    │   ✅ Gives exact line numbers                                   │
    └─────────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, custom_rules: str = None):
        """Initialize with optional custom rules YAML string."""
        self.custom_rules = custom_rules or SEMGREP_RULES_YAML
        self._rules_file = None
        self._check_semgrep_installed()
    
    def _check_semgrep_installed(self) -> bool:
        """Check if semgrep is installed."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            print("⚠️  Semgrep not installed. Install with: pip install semgrep")
            print("    Falling back to regex-based detection.")
            return False
    
    def _get_rules_file(self) -> str:
        """Create temporary rules file if needed."""
        if self._rules_file is None:
            fd, path = tempfile.mkstemp(suffix='.yaml', prefix='semgrep_rules_')
            with os.fdopen(fd, 'w') as f:
                f.write(self.custom_rules)
            self._rules_file = path
        return self._rules_file
    
    def analyze_content(self, content: str, filename: str) -> list:
        """
        Analyze code content with Semgrep.
        
        Returns list of findings with structure:
        {
            'rule_id': 'k8s-privileged-container',
            'message': 'Privileged container detected',
            'severity': 'ERROR',
            'line': 15,
            'code': 'privileged: true'
        }
        """
        findings = []
        
        # Create temp file with content
        suffix = Path(filename).suffix or '.yaml'
        if 'dockerfile' in filename.lower():
            suffix = '.dockerfile'
        
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix=suffix,
            delete=False
        ) as f:
            f.write(content)
            temp_file = f.name
        
        try:
            # Run semgrep
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", self._get_rules_file(),
                    "--json",
                    "--quiet",
                    temp_file
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 or result.stdout:
                output = json.loads(result.stdout) if result.stdout else {}
                
                for match in output.get('results', []):
                    findings.append({
                        'rule_id': match.get('check_id', ''),
                        'message': match.get('extra', {}).get('message', ''),
                        'severity': match.get('extra', {}).get('severity', 'INFO'),
                        'line': match.get('start', {}).get('line', 0),
                        'code': match.get('extra', {}).get('lines', '').strip(),
                        'cwe': match.get('extra', {}).get('metadata', {}).get('cwe', ''),
                    })
        
        except subprocess.TimeoutExpired:
            print(f"⚠️  Semgrep timeout analyzing {filename}")
        except json.JSONDecodeError:
            pass  # No findings or error in output
        except FileNotFoundError:
            # Semgrep not installed, use fallback
            findings = self._regex_fallback(content, filename)
        finally:
            os.unlink(temp_file)
        
        return findings
    
    def _regex_fallback(self, content: str, filename: str) -> list:
        """Fallback regex-based detection when Semgrep isn't available."""
        findings = []
        lines = content.split('\n')
        
        patterns = [
            (r'privileged:\s*true', 'k8s-privileged-container', 'Privileged container', 'ERROR'),
            (r'runAsUser:\s*0\b', 'k8s-run-as-root', 'Running as root', 'WARNING'),
            (r'allowPrivilegeEscalation:\s*true', 'k8s-privilege-escalation', 'Privilege escalation allowed', 'ERROR'),
            (r'hostNetwork:\s*true', 'k8s-host-network', 'Host network access', 'WARNING'),
            (r'hostPID:\s*true', 'k8s-host-pid', 'Host PID access', 'WARNING'),
            (r'readOnlyRootFilesystem:\s*false', 'k8s-writable-fs', 'Writable root filesystem', 'INFO'),
            (r'USER\s+root', 'docker-run-as-root', 'Running as root', 'WARNING'),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, rule_id, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': rule_id,
                        'message': message,
                        'severity': severity,
                        'line': i,
                        'code': line.strip(),
                    })
        
        return findings
    
    def compare_security_posture(self, before: str, after: str, filename: str) -> dict:
        """
        Compare security posture between before and after states.
        
        Returns:
        {
            'before_findings': [...],
            'after_findings': [...],
            'fixed': [...],      # Issues present in before but not after
            'introduced': [...], # Issues present in after but not before
            'direction': 'improved' | 'regressed' | 'neutral'
        }
        """
        before_findings = self.analyze_content(before, filename)
        after_findings = self.analyze_content(after, filename)
        
        # Compare by rule_id to find fixed/introduced issues
        before_rules = {f['rule_id'] for f in before_findings}
        after_rules = {f['rule_id'] for f in after_findings}
        
        fixed_rules = before_rules - after_rules
        introduced_rules = after_rules - before_rules
        
        fixed = [f for f in before_findings if f['rule_id'] in fixed_rules]
        introduced = [f for f in after_findings if f['rule_id'] in introduced_rules]
        
        # Determine direction
        severity_weight = {'ERROR': 3, 'WARNING': 2, 'INFO': 1}
        
        fixed_score = sum(severity_weight.get(f['severity'], 1) for f in fixed)
        introduced_score = sum(severity_weight.get(f['severity'], 1) for f in introduced)
        
        if fixed_score > introduced_score:
            direction = 'improved'
        elif introduced_score > fixed_score:
            direction = 'regressed'
        else:
            direction = 'neutral'
        
        return {
            'before_findings': before_findings,
            'after_findings': after_findings,
            'fixed': fixed,
            'introduced': introduced,
            'direction': direction,
            'fixed_count': len(fixed),
            'introduced_count': len(introduced),
        }
    
    def cleanup(self):
        """Remove temporary rules file."""
        if self._rules_file and os.path.exists(self._rules_file):
            os.unlink(self._rules_file)


# =============================================================================
# MAIN EXTRACTION FUNCTION (ENHANCED)
# =============================================================================

# Global analyzer instance (reuse for efficiency)
_semgrep_analyzer = None

def get_semgrep_analyzer() -> SemgrepAnalyzer:
    """Get or create the global Semgrep analyzer."""
    global _semgrep_analyzer
    if _semgrep_analyzer is None:
        _semgrep_analyzer = SemgrepAnalyzer()
    return _semgrep_analyzer


def extract_security_deltas(
    repo, 
    IAC_KEYWORDS, 
    limit=5,
    use_semgrep=True,      # NEW: Enable Semgrep analysis
    semgrep_only=False     # NEW: Only include commits with Semgrep findings
):
    """
    Extract security deltas from repository commits.
    
    Detection pipeline:
    ┌─────────────────────────────────────────────────────────────────┐
    │  1. Keyword Filter (fast pre-filter on commit messages)         │
    │                           ↓                                     │
    │  2. File Type Filter (only IaC files: yaml, Dockerfile, etc.)   │
    │                           ↓                                     │
    │  3. Semgrep Analysis (precise security pattern detection)       │
    │                           ↓                                     │
    │  4. Posture Comparison (before vs after)                        │
    └─────────────────────────────────────────────────────────────────┘
    
    Args:
        repo: PyGithub repo object
        IAC_KEYWORDS: List of keywords to filter commits
        limit: Max commits to process
        use_semgrep: Whether to run Semgrep analysis
        semgrep_only: If True, only include commits where Semgrep found issues
    
    Returns:
        List of delta dictionaries with security analysis
    """
    dataset = []
    commits = repo.get_commits()
    analyzer = get_semgrep_analyzer() if use_semgrep else None
    
    count = 0
    for commit in commits:
        msg = commit.commit.message.lower()
        
        # Step 1: Keyword pre-filter
        if not any(key in msg for key in IAC_KEYWORDS):
            continue
            
        print(f"Analyzing security delta in commit: {commit.sha[:7]}")
        
        parent = commit.parents[0] if commit.parents else None
        if not parent:
            continue
        
        for file in commit.files:
            # Step 2: File type filter
            if not file.filename.endswith(('.yaml', '.yml', 'Dockerfile', '.tf')):
                continue
            
            try:
                # Fetch before/after states
                before_code = repo.get_contents(
                    file.filename, ref=parent.sha
                ).decoded_content.decode()
                
                after_code = repo.get_contents(
                    file.filename, ref=commit.sha
                ).decoded_content.decode()
                
                # Build base entry
                entry = {
                    "commit_sha": commit.sha,
                    "commit_message": msg,
                    "file": file.filename,
                    "before": before_code,
                    "after": after_code,
                    "diff": file.patch,
                }
                
                # Step 3: Semgrep analysis (if enabled)
                if analyzer:
                    posture = analyzer.compare_security_posture(
                        before_code, after_code, file.filename
                    )
                    
                    entry["semgrep_analysis"] = {
                        "before_findings": posture['before_findings'],
                        "after_findings": posture['after_findings'],
                        "fixed": posture['fixed'],
                        "introduced": posture['introduced'],
                        "direction": posture['direction'],
                    }
                    
                    entry["security_posture"] = posture['direction']
                    entry["issues_fixed"] = posture['fixed_count']
                    entry["issues_introduced"] = posture['introduced_count']
                    
                    # If semgrep_only, skip entries without findings
                    if semgrep_only:
                        if not posture['before_findings'] and not posture['after_findings']:
                            continue
                    
                    # Print summary
                    if posture['fixed']:
                        print(f"  ✅ Fixed {len(posture['fixed'])} issues in {file.filename}")
                    if posture['introduced']:
                        print(f"  ⚠️  Introduced {len(posture['introduced'])} issues in {file.filename}")
                
                dataset.append(entry)
                
            except Exception as e:
                print(f"Error fetching delta for {file.filename}: {e}")
        
        count += 1
        if count >= limit:
            break
    
    return dataset


# =============================================================================
# ORIGINAL FUNCTIONS (kept for compatibility)
# =============================================================================

def format_deltas(jsonl_file="security_deltas.jsonl"):
    """
    Load and display security deltas in a nice BEFORE/AFTER format.
    Now includes Semgrep findings if available.
    """
    deltas = []
    with open(jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                deltas.append(json.loads(line))
    
    print(f"\n{'='*70}")
    print(f"SECURITY DELTAS REPORT - {len(deltas)} entries")
    print(f"{'='*70}")
    
    for i, delta in enumerate(deltas, 1):
        before_lines = []
        after_lines = []
        
        if delta.get('diff'):
            for line in delta['diff'].split('\n'):
                if line.startswith('-') and not line.startswith('---'):
                    before_lines.append(line[1:].strip())
                elif line.startswith('+') and not line.startswith('+++'):
                    after_lines.append(line[1:].strip())
        
        print(f"\n{'─'*70}")
        print(f"[{i}] File: {delta.get('file', 'unknown')}")
        print(f"    Commit: {delta.get('commit_message', '')[:60]}")
        
        # NEW: Show Semgrep analysis if available
        if delta.get('semgrep_analysis'):
            analysis = delta['semgrep_analysis']
            posture = delta.get('security_posture', 'unknown')
            
            posture_icon = {'improved': '✅', 'regressed': '⚠️', 'neutral': '➖'}.get(posture, '?')
            print(f"    Security Posture: {posture_icon} {posture.upper()}")
            
            if analysis.get('fixed'):
                print(f"    Fixed Issues:")
                for f in analysis['fixed'][:3]:  # Show max 3
                    print(f"      ✅ {f['rule_id']}: {f['message']}")
            
            if analysis.get('introduced'):
                print(f"    Introduced Issues:")
                for f in analysis['introduced'][:3]:
                    print(f"      ⚠️  {f['rule_id']}: {f['message']}")
        
        print()
        print("BEFORE:")
        if before_lines:
            for line in before_lines[:10]:
                print(f"    {line[:65]}")
            if len(before_lines) > 10:
                print(f"    ... and {len(before_lines) - 10} more lines")
        else:
            print("    (no lines removed)")
        
        print()
        print("AFTER:")
        if after_lines:
            for line in after_lines[:10]:
                print(f"    {line[:65]}")
            if len(after_lines) > 10:
                print(f"    ... and {len(after_lines) - 10} more lines")
        else:
            print("    (no lines added)")
        
        print(f"{'─'*70}")
    
    print(f"\n✅ Formatted {len(deltas)} security deltas\n")


def format_deltas_html(jsonl_file="security_deltas.jsonl", output_file="security_deltas.html"):
    """
    Generate HTML report with Semgrep findings highlighted.
    """
    deltas = []
    with open(jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                deltas.append(json.loads(line))
    
    # Count statistics
    improved = sum(1 for d in deltas if d.get('security_posture') == 'improved')
    regressed = sum(1 for d in deltas if d.get('security_posture') == 'regressed')
    
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Deltas Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0; padding: 20px; background: #f5f5f5;
        }
        .header {
            background: white; padding: 20px; border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;
            position: sticky; top: 0; z-index: 100;
        }
        h1 { color: #333; margin: 0 0 15px 0; }
        .stats {
            display: flex; gap: 15px; flex-wrap: wrap;
        }
        .stat {
            padding: 8px 15px; border-radius: 20px; font-size: 14px;
        }
        .stat.total { background: #2196F3; color: white; }
        .stat.improved { background: #4CAF50; color: white; }
        .stat.regressed { background: #f44336; color: white; }
        .controls {
            margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;
        }
        .search-box {
            flex: 1; min-width: 200px; padding: 10px 15px;
            border: 2px solid #ddd; border-radius: 6px; font-size: 14px;
        }
        .search-box:focus { outline: none; border-color: #2196F3; }
        .btn {
            padding: 10px 20px; border: none; border-radius: 6px;
            cursor: pointer; font-size: 14px;
        }
        .btn-secondary { background: #e0e0e0; color: #333; }
        .btn-secondary:hover { background: #bdbdbd; }
        
        .delta-card {
            background: white; border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 10px;
            overflow: hidden;
        }
        .delta-card.hidden { display: none; }
        .delta-header {
            padding: 15px; cursor: pointer;
            display: flex; justify-content: space-between; align-items: center;
        }
        .delta-header.improved { background: #e8f5e9; border-left: 4px solid #4CAF50; }
        .delta-header.regressed { background: #ffebee; border-left: 4px solid #f44336; }
        .delta-header.neutral { background: #fff3e0; border-left: 4px solid #ff9800; }
        .delta-header:hover { filter: brightness(0.95); }
        .delta-header h3 { margin: 0; font-size: 14px; }
        .delta-header .commit { font-size: 12px; color: #666; margin-top: 5px; }
        .delta-header .badges { display: flex; gap: 8px; }
        .badge {
            padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: bold;
        }
        .badge.fixed { background: #c8e6c9; color: #2e7d32; }
        .badge.introduced { background: #ffcdd2; color: #c62828; }
        .toggle { font-size: 18px; }
        .delta-card.collapsed .toggle { transform: rotate(-90deg); }
        
        .delta-content {
            max-height: 2000px; overflow: hidden; transition: max-height 0.3s;
        }
        .delta-card.collapsed .delta-content { max-height: 0; }
        
        .findings {
            padding: 15px; background: #fafafa; border-top: 1px solid #eee;
        }
        .finding {
            padding: 8px 12px; margin: 5px 0; border-radius: 4px; font-size: 13px;
        }
        .finding.fixed { background: #e8f5e9; border-left: 3px solid #4CAF50; }
        .finding.introduced { background: #ffebee; border-left: 3px solid #f44336; }
        .finding .rule { font-weight: bold; }
        .finding .message { color: #666; }
        
        .columns {
            display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0;
        }
        .column { padding: 15px; border-right: 1px solid #eee; }
        .column:last-child { border-right: none; }
        .column-header {
            font-weight: bold; margin-bottom: 10px; padding-bottom: 5px;
            border-bottom: 2px solid #ddd; font-size: 13px;
        }
        .before .column-header { color: #c62828; border-color: #c62828; }
        .after .column-header { color: #2e7d32; border-color: #2e7d32; }
        .diff .column-header { color: #1565c0; border-color: #1565c0; }
        pre {
            background: #f8f9fa; padding: 10px; border-radius: 4px;
            font-size: 11px; line-height: 1.4; margin: 0;
            white-space: pre-wrap; word-wrap: break-word;
            max-height: 300px; overflow-y: auto;
        }
        .before pre { background: #ffebee; }
        .after pre { background: #e8f5e9; }
        .diff pre { background: #e3f2fd; }
        .line-removed { background: #ffcdd2; display: block; }
        .line-added { background: #c8e6c9; display: block; }
        .empty { color: #999; font-style: italic; }
        
        @media (max-width: 1000px) {
            .columns { grid-template-columns: 1fr; }
            .column { border-right: none; border-bottom: 1px solid #eee; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Deltas Report</h1>
        <div class="stats">
            <span class="stat total">Total: """ + str(len(deltas)) + """</span>
            <span class="stat improved">✅ Improved: """ + str(improved) + """</span>
            <span class="stat regressed">⚠️ Regressed: """ + str(regressed) + """</span>
            <span class="stat" id="showingCount">Showing: """ + str(len(deltas)) + """</span>
        </div>
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="Search files, commits, findings...">
            <button class="btn btn-secondary" onclick="expandAll()">Expand All</button>
            <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
            <button class="btn btn-secondary" onclick="filterBy('improved')">Show Improved</button>
            <button class="btn btn-secondary" onclick="filterBy('regressed')">Show Regressed</button>
            <button class="btn btn-secondary" onclick="filterBy('')">Show All</button>
        </div>
    </div>
    <div id="container">
"""
    
    for i, delta in enumerate(deltas, 1):
        before_lines = []
        after_lines = []
        
        if delta.get('diff'):
            for line in delta['diff'].split('\n'):
                if line.startswith('-') and not line.startswith('---'):
                    before_lines.append(line[1:])
                elif line.startswith('+') and not line.startswith('+++'):
                    after_lines.append(line[1:])
        
        file_name = escape(delta.get('file', 'unknown'))
        commit_msg = escape(delta.get('commit_message', '').split('\n')[0][:80])
        posture = delta.get('security_posture', 'neutral')
        analysis = delta.get('semgrep_analysis', {})
        
        # Format findings badges
        fixed_count = delta.get('issues_fixed', 0)
        introduced_count = delta.get('issues_introduced', 0)
        
        badges_html = ""
        if fixed_count:
            badges_html += f'<span class="badge fixed">✅ {fixed_count} fixed</span>'
        if introduced_count:
            badges_html += f'<span class="badge introduced">⚠️ {introduced_count} new</span>'
        
        # Format findings section
        findings_html = ""
        if analysis.get('fixed') or analysis.get('introduced'):
            findings_html = '<div class="findings">'
            for f in analysis.get('fixed', []):
                findings_html += f'''
                    <div class="finding fixed">
                        <span class="rule">✅ FIXED: {escape(f.get("rule_id", ""))}</span>
                        <span class="message">{escape(f.get("message", ""))}</span>
                    </div>'''
            for f in analysis.get('introduced', []):
                findings_html += f'''
                    <div class="finding introduced">
                        <span class="rule">⚠️ NEW: {escape(f.get("rule_id", ""))}</span>
                        <span class="message">{escape(f.get("message", ""))}</span>
                    </div>'''
            findings_html += '</div>'
        
        # Format code sections
        before_html = '\n'.join(f'<span class="line-removed">{escape(l)}</span>' for l in before_lines) if before_lines else '<span class="empty">(no lines removed)</span>'
        after_html = '\n'.join(f'<span class="line-added">{escape(l)}</span>' for l in after_lines) if after_lines else '<span class="empty">(no lines added)</span>'
        
        diff_lines = []
        if delta.get('diff'):
            for line in delta['diff'].split('\n'):
                if line.startswith('@@'):
                    diff_lines.append(f'<span style="color:#1565c0;font-weight:bold">{escape(line)}</span>')
                elif line.startswith('-') and not line.startswith('---'):
                    diff_lines.append(f'<span class="line-removed">{escape(line)}</span>')
                elif line.startswith('+') and not line.startswith('+++'):
                    diff_lines.append(f'<span class="line-added">{escape(line)}</span>')
                elif not line.startswith('---') and not line.startswith('+++'):
                    diff_lines.append(escape(line))
        diff_html = '\n'.join(diff_lines) if diff_lines else '<span class="empty">(no diff)</span>'
        
        search_data = f"{file_name} {commit_msg} {' '.join(before_lines)} {' '.join(after_lines)}".lower()
        
        html += f"""
        <div class="delta-card collapsed" data-posture="{posture}" data-search="{escape(search_data)}">
            <div class="delta-header {posture}" onclick="toggleCard(this.parentElement)">
                <div>
                    <h3>{file_name}</h3>
                    <div class="commit">{commit_msg}</div>
                </div>
                <div class="badges">
                    {badges_html}
                    <span class="toggle">▼</span>
                </div>
            </div>
            <div class="delta-content">
                {findings_html}
                <div class="columns">
                    <div class="column before">
                        <div class="column-header">❌ BEFORE ({len(before_lines)} lines)</div>
                        <pre>{before_html}</pre>
                    </div>
                    <div class="column after">
                        <div class="column-header">✅ AFTER ({len(after_lines)} lines)</div>
                        <pre>{after_html}</pre>
                    </div>
                    <div class="column diff">
                        <div class="column-header">📝 DIFF</div>
                        <pre>{diff_html}</pre>
                    </div>
                </div>
            </div>
        </div>
"""
    
    html += """
    </div>
    <script>
        function toggleCard(card) { card.classList.toggle('collapsed'); }
        function expandAll() {
            document.querySelectorAll('.delta-card:not(.hidden)').forEach(c => c.classList.remove('collapsed'));
        }
        function collapseAll() {
            document.querySelectorAll('.delta-card').forEach(c => c.classList.add('collapsed'));
        }
        function filterBy(posture) {
            const cards = document.querySelectorAll('.delta-card');
            let visible = 0;
            cards.forEach(card => {
                if (!posture || card.dataset.posture === posture) {
                    card.classList.remove('hidden');
                    visible++;
                } else {
                    card.classList.add('hidden');
                }
            });
            document.getElementById('showingCount').textContent = 'Showing: ' + visible;
        }
        document.getElementById('searchBox').addEventListener('input', function() {
            const query = this.value.toLowerCase();
            const cards = document.querySelectorAll('.delta-card');
            let visible = 0;
            cards.forEach(card => {
                if (!query || card.dataset.search.includes(query)) {
                    card.classList.remove('hidden');
                    visible++;
                } else {
                    card.classList.add('hidden');
                }
            });
            document.getElementById('showingCount').textContent = 'Showing: ' + visible;
        });
    </script>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Saved HTML report to {output_file}")
    return output_file


# =============================================================================
# FUTURE: NLP/BERT-BASED DETECTION
# =============================================================================

"""
FUTURE ENHANCEMENT: NLP/BERT for Semantic Security Analysis
============================================================

Why NLP/BERT after Semgrep?
┌─────────────────────────────────────────────────────────────────────┐
│ Semgrep Limitations:                                                │
│   - Only catches patterns you explicitly write rules for            │
│   - Can't understand context or intent                              │
│   - Misses novel vulnerability patterns                             │
│                                                                     │
│ NLP/BERT Advantages:                                                │
│   - Semantic understanding of code and comments                     │
│   - Can classify unknown patterns based on similarity               │
│   - Context-aware (understands surrounding code)                    │
│   - Can learn from your labeled dataset                             │
└─────────────────────────────────────────────────────────────────────┘

Implementation approach:
1. Use your labeled dataset (before/after pairs) to fine-tune a model
2. Options:
   - CodeBERT (Microsoft): Pre-trained on code
   - SecureBERT: Pre-trained on security text
   - sentence-transformers: For semantic similarity

Example code (requires: pip install transformers torch sentence-transformers):

from sentence_transformers import SentenceTransformer
import numpy as np

class NLPSecurityAnalyzer:
    def __init__(self):
        # Use CodeBERT or similar model
        self.model = SentenceTransformer('microsoft/codebert-base')
        
        # Known vulnerability descriptions for similarity matching
        self.vuln_descriptions = [
            "privileged container with full host access",
            "running as root user without restrictions",
            "hardcoded password or secret in code",
            "disabled SSL certificate validation",
            "open network access from anywhere",
        ]
        self.vuln_embeddings = self.model.encode(self.vuln_descriptions)
    
    def analyze(self, code: str) -> list:
        # Encode the code
        code_embedding = self.model.encode(code)
        
        # Calculate similarity to known vulnerabilities
        similarities = np.dot(self.vuln_embeddings, code_embedding)
        
        findings = []
        for i, (desc, sim) in enumerate(zip(self.vuln_descriptions, similarities)):
            if sim > 0.7:  # Threshold
                findings.append({
                    'description': desc,
                    'confidence': float(sim),
                    'method': 'nlp_similarity'
                })
        
        return findings

This would be Phase 3 of your detection pipeline, after keywords and Semgrep.
"""


# =============================================================================
# CLEANUP
# =============================================================================

import atexit

def cleanup():
    """Cleanup temporary files on exit."""
    global _semgrep_analyzer
    if _semgrep_analyzer:
        _semgrep_analyzer.cleanup()

atexit.register(cleanup)