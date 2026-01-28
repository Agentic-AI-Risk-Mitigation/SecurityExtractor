#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
offline_funclib.py - Offline Git Repository Analysis Functions
==============================================================

For large repositories (10,000+ commits), clone locally and analyze offline.
No API rate limits, much faster than GitHub API!

Setup:
    1. Clone the repo:
       git clone https://github.com/kubernetes/kubernetes.git

    2. pip install gitpython

Usage:
    import offline_funclib as offline

    # Extract security deltas from local clone
    data = offline.extract_security_deltas_offline(
        repo_path="./kubernetes",
        keywords=IAC_KEYWORDS,
        limit=1000
    )
"""

import os
import re
import json
import difflib
from datetime import datetime
from pathlib import Path
from typing import Optional, Generator, Tuple, List, Dict
import git
from git import Repo
from format_stream2_html import format_security_deltas_html

# =============================================================================
# CONFIGURATION
# =============================================================================

REPO_PATH = "./kubernetes"         # Path to your cloned repository
LIMIT = 100                        # Number of security commits to process
BRANCH = "master"                  # Branch to analyze ("main" or "master")
SINCE = None                       # Optional: "2024-01-01" to filter by date
OUTPUT_FILE = "security_deltas.jsonl"
MESSAGES_ONLY = False              # Set True for faster extraction (no diffs)

# Default security keywords
DEFAULT_KEYWORDS = [
    # Vulnerability identifiers (high precision)
    "cve-", "cwe-", "ghsa-",
    "security advisory", "security bulletin",

    # General security terms
    "security", "vulnerability", "exploit", "insecure", "unsafe",
    "malicious", "attack", "breach", "compromise",

    # Fix indicators
    "fix", "patch", "remediate", "mitigate", "harden",

    # IaC specific
    "privileged", "rbac", "secret", "credential", "permission",
    "exposed", "encryption", "tls", "ssl", "password", "token",
    "hardcoded", "plaintext",

    # Common vulnerability types
    "injection", "xss", "csrf", "bypass", "overflow",
    "escalation", "disclosure", "unauthorized",
]

# File extensions to analyze
IAC_EXTENSIONS = {'.yaml', '.yml', '.json', '.tf', '.tfvars'}
IAC_FILENAMES = {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}

# Paths likely containing IaC files (for filtering)
IAC_PATHS = [
    'deploy/', 'deployment/', 'manifests/', 'k8s/', 'kubernetes/',
    'helm/', 'charts/', 'config/', 'terraform/', 'ansible/',
    'docker/', 'cluster/', 'hack/', 'test/fixtures/', 'examples/',
]

# Patterns to exclude (reduce false positives)
EXCLUDE_PATTERNS = [
    "bump version", "update readme", "typo", "spelling",
    "docs:", "test:", "style:", "chore:", "refactor:",
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def is_iac_file(filepath: str) -> bool:
    """Check if file is an Infrastructure-as-Code file."""
    path = Path(filepath)

    # Check filename
    if path.name in IAC_FILENAMES:
        return True

    # Check extension
    if path.suffix.lower() in IAC_EXTENSIONS:
        return True

    return False


def is_iac_path(filepath: str) -> bool:
    """Check if file is in an IaC-related directory."""
    filepath_lower = filepath.lower()
    return any(p in filepath_lower for p in IAC_PATHS)


def is_security_related(message: str, keywords: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if commit message indicates security-related changes.

    Returns:
        (is_security, matched_keywords)
    """
    msg_lower = message.lower()

    # Check exclusions first
    for exclude in EXCLUDE_PATTERNS:
        if exclude in msg_lower:
            return (False, [])

    # Find matches
    matched = [kw for kw in keywords if kw.lower() in msg_lower]
    return (len(matched) > 0, matched)


def get_file_content_at_commit(repo: 'Repo', commit, filepath: str) -> Optional[str]:
    """Get file content at a specific commit."""
    try:
        blob = commit.tree / filepath
        return blob.data_stream.read().decode('utf-8', errors='replace')
    except (KeyError, AttributeError, TypeError):
        return None


def generate_diff(before: str, after: str, filepath: str) -> str:
    """Generate unified diff between two file versions."""
    if not before or not after:
        return ""

    diff_lines = list(difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f'a/{filepath}',
        tofile=f'b/{filepath}',
        lineterm=''
    ))
    return '\n'.join(diff_lines)


# =============================================================================
# MAIN EXTRACTION FUNCTION (OFFLINE)
# =============================================================================

def extract_security_deltas_offline(
        repo_path: str,
        keywords: List[str] = None,
        limit: int = 100,
        branch: str = "main",
        since: str = None,
        iac_only: bool = True,
        iac_paths_only: bool = False,
        verbose: bool = True
) -> List[Dict]:
    """
    Extract security deltas from a locally cloned git repository.

    This is the OFFLINE equivalent of extract_security_deltas() in funclib.py.
    Much faster for large repositories (no API rate limits).

    Args:
        repo_path: Path to the cloned git repository
        keywords: Security keywords to search for (default: DEFAULT_KEYWORDS)
        limit: Maximum number of security commits to process
        branch: Git branch to analyze (default: "main")
        since: Only commits after this date (format: "2024-01-01")
        iac_only: Only analyze IaC files (yaml, Dockerfile, etc.)
        iac_paths_only: Further filter to only IaC directories
        verbose: Print progress information

    Returns:
        List of delta dictionaries (same format as funclib.extract_security_deltas)

    Example:
        data = extract_security_deltas_offline(
            repo_path="./kubernetes",
            keywords=["security", "cve-", "privileged"],
            limit=500
        )
    """

    if keywords is None:
        keywords = DEFAULT_KEYWORDS

    # Validate repo path
    repo_path = Path(repo_path)
    if not repo_path.exists():
        print(f"❌ Repository not found: {repo_path}")
        print(f"   Clone it first: git clone <url> {repo_path}")
        return []

    git_dir = repo_path / '.git'
    if not git_dir.exists():
        print(f"❌ Not a git repository: {repo_path}")
        return []

    # Open repository
    repo = Repo(repo_path)

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"OFFLINE SECURITY DELTA EXTRACTION")
        print(f"{'=' * 60}")
        print(f"Repository: {repo_path}")
        print(f"Branch: {branch}")
        print(f"Keywords: {len(keywords)} configured")
        print(f"Limit: {limit} commits")
        if since:
            print(f"Since: {since}")
        print(f"{'=' * 60}\n")

    # Get commits iterator
    try:
        commits_iter = repo.iter_commits(branch, max_count=limit * 20)  # Scan more to find enough
    except git.exc.GitCommandError:
        # Try master or HEAD if branch not found
        try:
            commits_iter = repo.iter_commits('master', max_count=limit * 20)
            if verbose:
                print(f"⚠️  Branch '{branch}' not found, using 'master'")
        except git.exc.GitCommandError:
            commits_iter = repo.iter_commits('HEAD', max_count=limit * 20)
            if verbose:
                print(f"⚠️  Using HEAD")

    # Parse since date if provided
    since_date = None
    if since:
        try:
            since_date = datetime.fromisoformat(since)
        except ValueError:
            print(f"⚠️  Invalid date format: {since}, ignoring")

    # Extract deltas
    dataset = []
    commits_scanned = 0
    security_commits_found = 0

    for commit in commits_iter:
        commits_scanned += 1

        # Progress indicator
        if verbose and commits_scanned % 500 == 0:
            print(f"  Scanned {commits_scanned} commits, found {security_commits_found} security-related...")

        # Date filter
        if since_date:
            commit_date = datetime.fromtimestamp(commit.committed_date)
            if commit_date < since_date:
                continue

        # Check if security-related
        is_security, matched_keywords = is_security_related(commit.message, keywords)
        if not is_security:
            continue

        security_commits_found += 1

        if verbose:
            print(f"  [{security_commits_found}] {commit.hexsha[:7]}: {commit.message.split(chr(10))[0][:50]}...")

        # Need parent for before/after comparison
        if not commit.parents:
            continue
        parent = commit.parents[0]

        # Get changed files
        try:
            diffs = parent.diff(commit)
        except Exception:
            continue

        for diff_item in diffs:
            filepath = diff_item.b_path or diff_item.a_path
            if not filepath:
                continue

            # Filter for IaC files
            if iac_only and not is_iac_file(filepath):
                continue

            # Optional: filter by path
            if iac_paths_only and not is_iac_path(filepath):
                continue

            # Get before/after content
            before_content = get_file_content_at_commit(repo, parent, filepath)
            after_content = get_file_content_at_commit(repo, commit, filepath)

            if not before_content and not after_content:
                continue

            # Generate diff
            diff_text = generate_diff(
                before_content or '',
                after_content or '',
                filepath
            )

            # Build delta entry (same format as funclib.py)
            entry = {
                "commit_sha": commit.hexsha,
                "commit_message": commit.message.strip(),
                "commit_date": datetime.fromtimestamp(commit.committed_date).isoformat(),
                "author": commit.author.name,
                "file": filepath,
                "before": before_content or "",
                "after": after_content or "",
                "diff": diff_text,
                "keywords_matched": matched_keywords,
            }

            dataset.append(entry)

        # Check limit
        if security_commits_found >= limit:
            if verbose:
                print(f"\n✅ Reached limit of {limit} security commits")
            break

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"EXTRACTION COMPLETE")
        print(f"{'=' * 60}")
        print(f"  Commits scanned:      {commits_scanned:,}")
        print(f"  Security commits:     {security_commits_found:,}")
        print(f"  Deltas extracted:     {len(dataset):,}")
        print(f"{'=' * 60}\n")

    return dataset


# =============================================================================
# COMMIT MESSAGE ANALYSIS
# =============================================================================

def extract_commit_messages(
        repo_path: str,
        keywords: List[str] = None,
        limit: int = 1000,
        branch: str = "main",
        verbose: bool = True
) -> List[Dict]:
    """
    Extract only commit messages (faster than full deltas).
    Good for initial analysis of what's in a repository.

    Returns:
        List of {sha, message, date, author, keywords_matched}
    """

    if keywords is None:
        keywords = DEFAULT_KEYWORDS

    repo = Repo(repo_path)

    try:
        commits = repo.iter_commits(branch, max_count=limit * 10)
    except git.exc.GitCommandError:
        commits = repo.iter_commits('HEAD', max_count=limit * 10)

    results = []
    count = 0

    for commit in commits:
        is_security, matched = is_security_related(commit.message, keywords)

        if is_security:
            results.append({
                "sha": commit.hexsha,
                "message": commit.message.strip(),
                "date": datetime.fromtimestamp(commit.committed_date).isoformat(),
                "author": commit.author.name,
                "keywords_matched": matched,
            })
            count += 1

            if verbose and count % 100 == 0:
                print(f"  Found {count} security commits...")

            if count >= limit:
                break

    if verbose:
        print(f"✅ Found {len(results)} security-related commits")

    return results


def analyze_commit_patterns(commits: List[Dict]) -> Dict:
    """
    Analyze patterns in commit messages.

    Returns statistics about keywords, authors, dates, etc.
    """

    # Keyword frequency
    keyword_counts = {}
    for c in commits:
        for kw in c.get('keywords_matched', []):
            keyword_counts[kw] = keyword_counts.get(kw, 0) + 1

    # Author frequency
    author_counts = {}
    for c in commits:
        author = c.get('author', 'unknown')
        author_counts[author] = author_counts.get(author, 0) + 1

    # Commits by year/month
    by_month = {}
    for c in commits:
        date_str = c.get('date', '')[:7]  # YYYY-MM
        by_month[date_str] = by_month.get(date_str, 0) + 1

    return {
        'total_commits': len(commits),
        'top_keywords': sorted(keyword_counts.items(), key=lambda x: -x[1])[:20],
        'top_authors': sorted(author_counts.items(), key=lambda x: -x[1])[:10],
        'by_month': dict(sorted(by_month.items())),
    }


# =============================================================================
# BUG REPORT / ISSUE ANALYSIS (from commit messages)
# =============================================================================

def extract_issue_references(commits: List[Dict]) -> List[Dict]:
    """
    Extract issue/bug references from commit messages.

    Looks for patterns like:
    - #1234
    - fixes #1234
    - closes #1234
    - kubernetes/kubernetes#1234
    - https://github.com/.../issues/1234
    """

    patterns = [
        (r'(?:fixes|closes|resolves|fix|close)\s*#(\d+)', 'fix_reference'),
        (r'(?<![\w/])#(\d+)(?!\d)', 'issue_reference'),
        (r'([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)#(\d+)', 'cross_repo_reference'),
        (r'github\.com/[^/]+/[^/]+/issues/(\d+)', 'url_reference'),
        (r'CVE-(\d{4}-\d{4,})', 'cve_reference'),
    ]

    results = []

    for commit in commits:
        message = commit.get('message', '')
        refs = []

        for pattern, ref_type in patterns:
            matches = re.findall(pattern, message, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    refs.append({'type': ref_type, 'value': '/'.join(match)})
                else:
                    refs.append({'type': ref_type, 'value': match})

        if refs:
            results.append({
                'sha': commit.get('sha'),
                'message': message[:200],
                'references': refs,
            })

    return results


# =============================================================================
# SAVE FUNCTIONS
# =============================================================================

def save_jsonl(data: List[Dict], filepath: str):
    """Save data to JSONL format (one JSON per line)."""
    with open(filepath, 'w', encoding='utf-8') as f:
        for entry in data:
            f.write(json.dumps(entry, default=str, ensure_ascii=False) + '\n')
    print(f"✅ Saved {len(data)} entries to {filepath}")


def save_json(data, filepath: str):
    """Save data to JSON format (pretty-printed)."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    print(f"✅ Saved to {filepath}")


def load_jsonl(filepath: str) -> List[Dict]:
    """Load data from JSONL file."""
    data = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data


# =============================================================================
# MAIN - Example usage when run directly
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Offline Git Security Analysis')
    parser.add_argument('repo_path', help='Path to cloned git repository')
    parser.add_argument('--limit', '-l', type=int, default=100,
                        help='Max security commits to process')
    parser.add_argument('--branch', '-b', default='main',
                        help='Branch to analyze')
    parser.add_argument('--since', '-s', help='Only commits after date (YYYY-MM-DD)')
    parser.add_argument('--output', '-o', default='security_deltas.jsonl',
                        help='Output file')
    parser.add_argument('--messages-only', action='store_true',
                        help='Only extract commit messages (faster)')

    args = parser.parse_args()

    if args.messages_only:
        # Fast: just get commit messages
        data = extract_commit_messages(
            args.repo_path,
            limit=args.limit,
            branch=args.branch
        )

        # Analyze patterns
        analysis = analyze_commit_patterns(data)
        print(f"\n📊 Top Keywords:")
        for kw, count in analysis['top_keywords'][:10]:
            print(f"   {kw}: {count}")

        # Extract issue references
        issues = extract_issue_references(data)
        print(f"\n🔗 Found {len(issues)} commits with issue references")

        save_jsonl(data, args.output.replace('.jsonl', '_messages.jsonl'))

    else:
        # Full: extract file deltas
        data = extract_security_deltas_offline(
            args.repo_path,
            limit=args.limit,
            branch=args.branch,
            since=args.since
        )

        save_jsonl(data, args.output)

    print(f"\n✅ Done! Extracted {len(data)} entries")

    format_security_deltas_html("security_deltas.jsonl", "stream2_report.html")