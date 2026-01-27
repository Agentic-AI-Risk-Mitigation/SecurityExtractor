#!/usr/bin/env python3
"""
Simple IaC Security Delta Extractor
====================================

A minimal, easy-to-understand script for extracting security-related
changes from IaC repositories. Perfect for getting started quickly.

Install: pip install PyGithub
Usage:   python simple_iac_extractor.py
"""

import os
import re
import json
from github import Github

# =============================================================================
# CONFIGURATION - Edit these!
# =============================================================================

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', 'your_token_here')

# Repositories to scan (pick one or more)
REPOS_TO_SCAN = [
    'kubernetes/examples',      # Good for K8s configs
    # 'hashicorp/terraform',    # Good for Terraform
    # 'ansible/ansible',        # Good for Ansible
]

# How many security commits to process per repo
MAX_COMMITS = 10

# Keywords that indicate security-related commits
SECURITY_KEYWORDS = [
    'security', 
    'fix', 
    'vuln', 
    'cve', 
    'rbac', 
    'secret', 
    'auth', 
    'permission', 
    'privilege', 
    'encrypt', 
    'tls'
]

# IaC file extensions to look for
IAC_EXTENSIONS = ('.tf', 
                  '.yaml', 
                  '.yml', 
                  'Dockerfile', 
                  '.j2')

# =============================================================================
# SECURITY PATTERN DETECTION
# =============================================================================

# Patterns that indicate PERMISSIVE (potentially insecure) settings
PERMISSIVE_PATTERNS = [
    # Kubernetes
    (r'privileged:\s*true', 'Privileged container', 'high'),
    (r'runAsUser:\s*0', 'Running as root', 'high'),
    (r'hostNetwork:\s*true', 'Host network access', 'high'),
    (r'allowPrivilegeEscalation:\s*true', 'Privilege escalation allowed', 'medium'),
    (r'readOnlyRootFilesystem:\s*false', 'Writable root filesystem', 'medium'),
    
    # Terraform
    (r'publicly_accessible\s*=\s*true', 'Publicly accessible resource', 'high'),
    (r'encrypted\s*=\s*false', 'Encryption disabled', 'high'),
    (r'cidr_block\s*=\s*["\']0\.0\.0\.0/0', 'Open to entire internet', 'critical'),
    
    # Docker
    (r'USER\s+root', 'Running as root', 'high'),
    (r'--privileged', 'Privileged mode', 'critical'),
    
    # General
    (r'password\s*[:=]\s*["\'][^${\s]', 'Hardcoded password', 'critical'),
    (r'(api_key|secret_key)\s*[:=]\s*["\'][^${\s]', 'Hardcoded secret', 'critical'),
]

# Patterns that indicate RESTRICTIVE (secure) settings
RESTRICTIVE_PATTERNS = [
    # Kubernetes
    (r'privileged:\s*false', 'Non-privileged container', 'good'),
    (r'runAsNonRoot:\s*true', 'Running as non-root', 'good'),
    (r'readOnlyRootFilesystem:\s*true', 'Read-only root filesystem', 'good'),
    (r'allowPrivilegeEscalation:\s*false', 'Privilege escalation blocked', 'good'),
    
    # Terraform
    (r'encrypted\s*=\s*true', 'Encryption enabled', 'good'),
    (r'publicly_accessible\s*=\s*false', 'Not publicly accessible', 'good'),
    
    # Docker
    (r'USER\s+\d+', 'Running as non-root UID', 'good'),
]


def find_patterns(content: str, patterns: list) -> list:
    """Find all matching patterns in content."""
    found = []
    lines = content.split('\n')
    
    for pattern, description, severity in patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                found.append({
                    'line': i,
                    'content': line.strip()[:80],
                    'description': description,
                    'severity': severity,
                })
    return found


def analyze_security_posture(before: str, after: str) -> dict:
    """
    Compare security posture before and after a change.
    Returns a dict with:
    - direction: 'improved', 'regressed', or 'neutral'
    - details: what changed
    """
    before_permissive = find_patterns(before, PERMISSIVE_PATTERNS)
    before_restrictive = find_patterns(before, RESTRICTIVE_PATTERNS)
    after_permissive = find_patterns(after, PERMISSIVE_PATTERNS)
    after_restrictive = find_patterns(after, RESTRICTIVE_PATTERNS)
    
    # Simple scoring: more permissive = bad, more restrictive = good
    severity_score = {'critical': 10, 'high': 5, 'medium': 2, 'good': 0}
    
    before_risk = sum(severity_score.get(p['severity'], 0) for p in before_permissive)
    after_risk = sum(severity_score.get(p['severity'], 0) for p in after_permissive)
    
    risk_change = after_risk - before_risk
    
    if risk_change > 0:
        direction = 'regressed'  # Security got worse
        summary = f"⚠️ Security WEAKENED (risk +{risk_change})"
    elif risk_change < 0:
        direction = 'improved'   # Security got better
        summary = f"✅ Security IMPROVED (risk {risk_change})"
    else:
        direction = 'neutral'
        summary = "No significant security posture change"
    
    return {
        'direction': direction,
        'risk_change': risk_change,
        'summary': summary,
        'before_issues': len(before_permissive),
        'after_issues': len(after_permissive),
        'before_safeguards': len(before_restrictive),
        'after_safeguards': len(after_restrictive),
    }


# =============================================================================
# MAIN EXTRACTION LOGIC
# =============================================================================

def extract_security_deltas(repo_name: str, limit: int = 10) -> list:
    """
    Extract security-related code changes from a repository.
    
    Returns a list of deltas with before/after states and analysis.
    """
    print(f"\n{'='*60}")
    print(f"Scanning: {repo_name}")
    print(f"{'='*60}")
    
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(repo_name)
    
    dataset = []
    security_commits_found = 0
    
    for commit in repo.get_commits():
        msg = commit.commit.message.lower()
        
        # Check if commit message contains security keywords
        keywords_found = [kw for kw in SECURITY_KEYWORDS if kw in msg]
        if not keywords_found:
            continue
        
        security_commits_found += 1
        print(f"\n[{security_commits_found}] {commit.sha[:8]}: {msg[:50]}...")
        print(f"    Keywords: {keywords_found}")
        
        # Need parent commit to get "before" state
        if not commit.parents:
            print("    ⚠️ Skipping (no parent)")
            continue
        
        parent_sha = commit.parents[0].sha
        
        # Check each changed file
        for file in commit.files:
            # Only process IaC files
            if not file.filename.endswith(IAC_EXTENSIONS):
                continue
            
            print(f"    📄 {file.filename}")
            
            try:
                # Get content BEFORE the fix (from parent commit)
                before_content = repo.get_contents(
                    file.filename, ref=parent_sha
                ).decoded_content.decode('utf-8', errors='replace')
                
                # Get content AFTER the fix (from this commit)  
                after_content = repo.get_contents(
                    file.filename, ref=commit.sha
                ).decoded_content.decode('utf-8', errors='replace')
                
            except Exception as e:
                print(f"       ⚠️ Error: {e}")
                continue
            
            # Analyze security posture change
            posture = analyze_security_posture(before_content, after_content)
            print(f"       {posture['summary']}")
            
            # Build the dataset entry
            entry = {
                # Identification
                'commit_sha': commit.sha,
                'parent_sha': parent_sha,
                'repository': repo_name,
                'filename': file.filename,
                
                # Content (the actual code)
                'before_state': before_content,
                'after_state': after_content,
                'diff': file.patch,
                
                # Metadata
                'commit_message': commit.commit.message,
                'commit_date': str(commit.commit.author.date),
                'keywords_matched': keywords_found,
                
                # Security analysis
                'posture_analysis': posture,
                
                # Labels for ML training
                'labels': {
                    'is_security_improvement': posture['direction'] == 'improved',
                    'is_security_regression': posture['direction'] == 'regressed',
                    'risk_change': posture['risk_change'],
                }
            }
            
            dataset.append(entry)
        
        # Stop after reaching limit
        if security_commits_found >= limit:
            print(f"\n✅ Reached limit of {limit} commits")
            break
    
    return dataset


def save_dataset(data: list, filename: str = 'iac_security_dataset.jsonl'):
    """Save dataset to JSONL file (one JSON per line)"""
    with open(filename, 'w', encoding='utf-8') as f:
        for entry in data:
            f.write(json.dumps(entry, default=str) + '\n')
    
    print(f"\n✅ Saved {len(data)} entries to {filename}")


def print_summary(data: list):
    """Print a summary of the extracted data"""
    if not data:
        print("\n⚠️ No data extracted!")
        return
    
    improvements = sum(1 for d in data if d['labels']['is_security_improvement'])
    regressions = sum(1 for d in data if d['labels']['is_security_regression'])
    neutral = len(data) - improvements - regressions
    
    print(f"""
{'='*60}
EXTRACTION SUMMARY
{'='*60}
Total entries:           {len(data)}
Security improvements:   {improvements} ✅
Security regressions:    {regressions} ⚠️
Neutral changes:         {neutral}
{'='*60}
    """)


# =============================================================================
# RUN IT!
# =============================================================================

if __name__ == '__main__':
    # Check for token
    if GITHUB_TOKEN == 'your_token_here':
        print("❌ Please set your GitHub token!")
        print("   Option 1: Edit GITHUB_TOKEN in this script")
        print("   Option 2: Set GITHUB_TOKEN environment variable")
        print("   Get a token at: https://github.com/settings/tokens")
        exit(1)
    
    # Extract from all configured repos
    all_data = []
    
    for repo in REPOS_TO_SCAN:
        data = extract_security_deltas(repo, limit=MAX_COMMITS)
        all_data.extend(data)
    
    # Save and summarize
    save_dataset(all_data)
    print_summary(all_data)
    
    # Also save a pretty-printed JSON for easy inspection
    with open('iac_security_dataset.json', 'w') as f:
        json.dump(all_data, f, indent=2, default=str)
    print(f"✅ Also saved pretty-printed version to iac_security_dataset.json")
    
    