#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keyword_analyzer.py - Commit Message Keyword Frequency Analysis
===============================================================

Analyzes commit messages to find relevant security keywords.
Creates frequency visualizations (bar charts) and word clouds.

Usage:
    python3 keyword_analyzer.py

Dependencies:
    pip install matplotlib wordcloud
"""

import json
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict
import matplotlib.pyplot as plt
from wordcloud import WordCloud

# =============================================================================
# STOP WORDS (Common English words to exclude)
# =============================================================================

STOP_WORDS = {
    # Articles & Determiners
    'a', 'an', 'the', 'this', 'that', 'these', 'those',

    # Pronouns
    'i', 'me', 'my', 'we', 'our', 'you', 'your', 'he', 'she', 'it', 'they',
    'him', 'her', 'its', 'them', 'his', 'their', 'who', 'which', 'what',

    # Prepositions
    'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'up', 'down',
    'into', 'through', 'during', 'before', 'after', 'above', 'below', 'between',
    'under', 'over', 'out', 'off', 'about', 'against', 'within', 'without',

    # Conjunctions
    'and', 'or', 'but', 'nor', 'so', 'yet', 'both', 'either', 'neither',
    'not', 'only', 'also', 'as', 'if', 'when', 'while', 'although', 'because',
    'unless', 'until', 'whether', 'though', 'since', 'than',

    # Verbs (common/auxiliary)
    'is', 'are', 'was', 'were', 'be', 'been', 'being', 'am',
    'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing',
    'will', 'would', 'could', 'should', 'may', 'might', 'must', 'shall',
    'can', 'cannot', "can't", "won't", "don't", "doesn't", "didn't",
    'get', 'got', 'getting', 'make', 'made', 'making',

    # Common verbs in commits
    'add', 'added', 'adding', 'adds',
    'remove', 'removed', 'removing', 'removes',
    'change', 'changed', 'changing', 'changes',
    'update', 'updated', 'updating', 'updates',
    'use', 'used', 'using', 'uses',
    'set', 'sets', 'setting',
    'move', 'moved', 'moving', 'moves',

    # Adverbs
    'very', 'really', 'just', 'now', 'then', 'here', 'there', 'where',
    'always', 'never', 'often', 'sometimes', 'usually', 'already',
    'still', 'even', 'well', 'back', 'more', 'most', 'less', 'least',

    # Other common words
    'all', 'any', 'some', 'no', 'none', 'every', 'each', 'few', 'many',
    'much', 'other', 'another', 'such', 'same', 'different',
    'new', 'old', 'first', 'last', 'next', 'previous',
    'one', 'two', 'three', 'four', 'five', 'once', 'twice',
    'like', 'want', 'need', 'know', 'think', 'see', 'look',
    'way', 'thing', 'things', 'something', 'nothing', 'everything',
    'time', 'times', 'day', 'days', 'year', 'years',
    'part', 'parts', 'place', 'case', 'cases',
    'etc', 'eg', 'ie', 'vs', 'via',

    # Git/commit specific stop words
    'commit', 'commits', 'pr', 'pull', 'request', 'merge', 'merged', 'merging',
    'branch', 'branches', 'master', 'main', 'head', 'origin',
    'ref', 'refs', 'sha', 'hash',
    'file', 'files', 'folder', 'folders', 'directory', 'directories', 'dir',
    'line', 'lines', 'code', 'codes',
    'see', 'also', 'note', 'notes', 'todo', 'fixme',
    'wip', 'tmp', 'temp', 'test', 'tests', 'testing',
    'doc', 'docs', 'documentation', 'readme',
    'version', 'versions', 'v1', 'v2', 'v3',
    'http', 'https', 'www', 'com', 'org', 'io',

    # Numbers and single characters
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
}

# Security-related keywords to HIGHLIGHT (not exclude)
SECURITY_KEYWORDS = {
    'security', 'secure', 'insecure', 'unsafe', 'safe',
    'vulnerability', 'vulnerable', 'vuln', 'cve', 'cwe',
    'exploit', 'attack', 'attacker', 'malicious', 'threat',
    'fix', 'patch', 'hotfix', 'remediate', 'mitigate',
    'privilege', 'privileged', 'escalation', 'root', 'admin',
    'permission', 'permissions', 'rbac', 'acl', 'access',
    'authentication', 'authorization', 'auth', 'login', 'password',
    'credential', 'credentials', 'secret', 'secrets', 'token', 'tokens',
    'encrypt', 'encryption', 'decrypt', 'decryption', 'tls', 'ssl', 'https',
    'injection', 'xss', 'csrf', 'sqli', 'rce',
    'bypass', 'leak', 'leaks', 'exposure', 'exposed', 'disclosure',
    'sanitize', 'validate', 'validation', 'escape', 'filter',
    'container', 'pod', 'kubernetes', 'k8s', 'docker', 'helm',
    'network', 'firewall', 'ingress', 'egress', 'port', 'ports',
    'deny', 'allow', 'block', 'restrict', 'restricted',
    'audit', 'logging', 'monitor', 'monitoring',
    'hardcoded', 'plaintext', 'cleartext',
}


# =============================================================================
# KEYWORD EXTRACTION
# =============================================================================

def extract_words(text: str) -> List[str]:
    """Extract words from text, lowercase and clean."""
    # Remove URLs
    text = re.sub(r'https?://\S+', '', text)
    # Remove email addresses
    text = re.sub(r'\S+@\S+', '', text)
    # Remove special characters but keep hyphens in words
    text = re.sub(r'[^a-zA-Z0-9\s\-]', ' ', text)
    # Split into words
    words = text.lower().split()
    # Filter short words and clean
    words = [w.strip('-') for w in words if len(w.strip('-')) > 1]
    return words


def analyze_keywords(
        messages: List[str],
        exclude_stop_words: bool = True,
        min_word_length: int = 2
) -> Dict:
    """
    Analyze keyword frequency in commit messages.

    Returns:
        {
            'all_words': Counter of all words,
            'filtered_words': Counter excluding stop words,
            'security_words': Counter of security-related words only,
            'total_messages': int,
            'total_words': int
        }
    """
    all_words = Counter()
    security_words = Counter()

    for msg in messages:
        words = extract_words(msg)
        all_words.update(words)

        # Count security keywords
        for word in words:
            if word in SECURITY_KEYWORDS:
                security_words[word] += 1

    # Filter stop words
    if exclude_stop_words:
        filtered_words = Counter({
            word: count for word, count in all_words.items()
            if word not in STOP_WORDS and len(word) >= min_word_length
        })
    else:
        filtered_words = all_words

    return {
        'all_words': all_words,
        'filtered_words': filtered_words,
        'security_words': security_words,
        'total_messages': len(messages),
        'total_words': sum(all_words.values()),
        'unique_words': len(all_words),
    }


# =============================================================================
# VISUALIZATION
# =============================================================================

def plot_keyword_frequency(
        word_counts: Counter,
        title: str = "Keyword Frequency",
        top_n: int = 100,
        output_file: str = "keyword_frequency.png",
        highlight_security: bool = True,
        figsize: tuple = (20, 23)
):
    """
    Create a horizontal bar chart of keyword frequencies.
    Security-related keywords are highlighted in red.
    """

    # Get top N words
    top_words = word_counts.most_common(top_n)

    if not top_words:
        print("⚠️ No words to plot")
        return None

    words = [w[0] for w in top_words]
    counts = [w[1] for w in top_words]

    # Determine colors (red for security keywords, blue for others)
    if highlight_security:
        colors = ['#c62828' if w in SECURITY_KEYWORDS else '#1565c0' for w in words]
    else:
        colors = '#1565c0'

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    # Create horizontal bar chart (reversed so highest is at top)
    y_pos = range(len(words))
    bars = ax.barh(y_pos, counts[::-1], color=colors[::-1])

    # Customize
    ax.set_yticks(y_pos)
    ax.set_yticklabels(words[::-1], fontsize=10)
    ax.set_xlabel('Frequency', fontsize=12)
    ax.set_title(title, fontsize=14, fontweight='bold')

    # Add count labels on bars
    for i, (bar, count) in enumerate(zip(bars, counts[::-1])):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                str(count), va='center', fontsize=9)

    # Add legend
    if highlight_security:
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#c62828', label='Security-related'),
            Patch(facecolor='#1565c0', label='Other')
        ]
        ax.legend(handles=legend_elements, loc='lower right')

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"✅ Saved frequency chart to {output_file}")
    return output_file


def plot_security_keywords(
        security_counts: Counter,
        title: str = "Security Keywords Frequency",
        output_file: str = "security_keywords.png",
        figsize: tuple = (12, 6)
):
    """Create a bar chart specifically for security keywords."""

    if not security_counts:
        print("⚠️ No security keywords found")
        return None

    top_words = security_counts.most_common(25)
    words = [w[0] for w in top_words]
    counts = [w[1] for w in top_words]

    fig, ax = plt.subplots(figsize=figsize)

    y_pos = range(len(words))
    bars = ax.barh(y_pos, counts[::-1], color='#c62828')

    ax.set_yticks(y_pos)
    ax.set_yticklabels(words[::-1], fontsize=10)
    ax.set_xlabel('Frequency', fontsize=12)
    ax.set_title(title, fontsize=14, fontweight='bold', color='#c62828')

    for i, (bar, count) in enumerate(zip(bars, counts[::-1])):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(count), va='center', fontsize=9)

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"✅ Saved security keywords chart to {output_file}")
    return output_file


def create_wordcloud(
        word_counts: Counter,
        title: str = "Commit Message Word Cloud",
        output_file: str = "wordcloud.png",
        figsize: tuple = (16, 8)
):
    """Create a word cloud visualization."""

    if not word_counts:
        return None

    # Custom color function - red for security words
    def color_func(word, **kwargs):
        if word.lower() in SECURITY_KEYWORDS:
            return '#c62828'  # Red for security
        return '#1565c0'  # Blue for others

    wc = WordCloud(
        width=1600,
        height=800,
        background_color='white',
        max_words=150,
        color_func=color_func,
        prefer_horizontal=0.7,
    )

    wc.generate_from_frequencies(word_counts)

    fig, ax = plt.subplots(figsize=figsize)
    ax.imshow(wc, interpolation='bilinear')
    ax.axis('off')
    ax.set_title(title, fontsize=16, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"✅ Saved word cloud to {output_file}")
    return output_file


def generate_html_report(
        analysis: Dict,
        output_file: str = "keyword_analysis.html",
        chart_files: Dict = None
):
    """Generate an HTML report with embedded charts."""

    top_all = analysis['filtered_words'].most_common(50)
    top_security = analysis['security_words'].most_common(30)

    # Create HTML tables
    all_words_html = ""
    for i, (word, count) in enumerate(top_all, 1):
        is_security = word in SECURITY_KEYWORDS
        style = 'color: #c62828; font-weight: bold;' if is_security else ''
        all_words_html += f'<tr><td>{i}</td><td style="{style}">{word}</td><td>{count}</td></tr>'

    security_words_html = ""
    for i, (word, count) in enumerate(top_security, 1):
        security_words_html += f'<tr><td>{i}</td><td style="color: #c62828; font-weight: bold;">{word}</td><td>{count}</td></tr>'

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Keyword Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        h1, h2 {{ color: #333; }}
        .stats {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .stat-box {{ display: inline-block; background: #e3f2fd; padding: 15px 25px; margin: 5px; border-radius: 8px; }}
        .stat-box.security {{ background: #ffebee; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #1565c0; }}
        .stat-box.security .stat-value {{ color: #c62828; }}
        .stat-label {{ font-size: 12px; color: #666; }}
        table {{ border-collapse: collapse; width: 100%; background: white; }}
        th {{ background: #1565c0; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f5f5f5; }}
        .charts {{ display: flex; flex-wrap: wrap; gap: 20px; }}
        .chart {{ background: white; padding: 15px; border-radius: 8px; }}
        .chart img {{ max-width: 100%; height: auto; }}
        .columns {{ display: flex; gap: 20px; }}
        .column {{ flex: 1; }}
    </style>
</head>
<body>
    <h1>📊 Commit Message Keyword Analysis</h1>

    <div class="stats">
        <div class="stat-box">
            <div class="stat-value">{analysis['total_messages']:,}</div>
            <div class="stat-label">Total Messages</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{analysis['total_words']:,}</div>
            <div class="stat-label">Total Words</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{analysis['unique_words']:,}</div>
            <div class="stat-label">Unique Words</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{len(analysis['filtered_words']):,}</div>
            <div class="stat-label">After Stop Words Removed</div>
        </div>
        <div class="stat-box security">
            <div class="stat-value">{sum(analysis['security_words'].values()):,}</div>
            <div class="stat-label">Security Keyword Occurrences</div>
        </div>
    </div>

    <div class="columns">
        <div class="column">
            <h2>🔤 Top Keywords (All)</h2>
            <p>Red = security-related</p>
            <table>
                <tr><th>#</th><th>Word</th><th>Count</th></tr>
                {all_words_html}
            </table>
        </div>
        <div class="column">
            <h2>🔒 Security Keywords Only</h2>
            <p>Keywords relevant to Stream 2 research</p>
            <table>
                <tr><th>#</th><th>Word</th><th>Count</th></tr>
                {security_words_html}
            </table>
        </div>
    </div>

    <h2>📈 Visualizations</h2>
    <p>Charts saved as PNG files in the same directory.</p>

</body>
</html>
"""

    with open(output_file, 'w') as f:
        f.write(html)

    print(f"✅ Saved HTML report to {output_file}")
    return output_file


# =============================================================================
# DATA LOADING
# =============================================================================

def load_messages_from_jsonl(filepath: str) -> List[str]:
    """Load commit messages from JSONL file."""
    messages = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                msg = data.get('commit_message') or data.get('message', '')
                if msg:
                    messages.append(msg)
    return messages


def print_top_keywords(word_counts: Counter, title: str, top_n: int = 30):
    """Print top keywords to console."""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print(f"{'=' * 60}")

    for i, (word, count) in enumerate(word_counts.most_common(top_n), 1):
        is_security = word in SECURITY_KEYWORDS
        marker = "🔒" if is_security else "  "
        bar = "█" * min(count // 5, 30)
        print(f"{marker} {i:2}. {word:<25} {count:>5} {bar}")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":

    # =========================================================================
    # CONFIGURATION - Edit these values!
    # =========================================================================

    INPUT_FILE = "security_deltas.jsonl"  # Your JSONL file with commit messages
    OUTPUT_PREFIX = "keyword_analysis"  # Prefix for output files
    TOP_N = 100  # Number of top keywords to show

    # =========================================================================
    # EXECUTION
    # =========================================================================

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║           COMMIT MESSAGE KEYWORD ANALYZER                        ║
╚══════════════════════════════════════════════════════════════════╝
    """)

    # Check if file exists
    if not Path(INPUT_FILE).exists():
        print(f"❌ File not found: {INPUT_FILE}")
        print(f"   Please set INPUT_FILE to your JSONL file path")
        exit(1)

    # Load messages
    print(f"📂 Loading messages from {INPUT_FILE}...")
    messages = load_messages_from_jsonl(INPUT_FILE)
    print(f"   Loaded {len(messages)} commit messages")

    # Analyze keywords
    print(f"\n🔍 Analyzing keywords...")
    analysis = analyze_keywords(messages, exclude_stop_words=True)

    # Print to console
    print_top_keywords(analysis['filtered_words'], "TOP KEYWORDS (Stop words excluded)", TOP_N)
    print_top_keywords(analysis['security_words'], "SECURITY KEYWORDS ONLY", 25)

    # Create visualizations
    print(f"\n📊 Creating visualizations...")

    plot_keyword_frequency(
        analysis['filtered_words'],
        title=f"Top {TOP_N} Keywords in Security Commit Messages",
        top_n=TOP_N,
        output_file=f"{OUTPUT_PREFIX}_frequency.png"
    )

    plot_security_keywords(
        analysis['security_words'],
        title="Security-Related Keywords Frequency",
        output_file=f"{OUTPUT_PREFIX}_security.png"
    )

    create_wordcloud(
            analysis['filtered_words'],
            title="Commit Message Word Cloud",
            output_file=f"{OUTPUT_PREFIX}_wordcloud.png"
        )

    # Generate HTML report
    generate_html_report(
        analysis,
        output_file=f"{OUTPUT_PREFIX}.html"
    )

    # Summary
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                        ANALYSIS COMPLETE                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Messages analyzed:     {analysis['total_messages']:<40} ║
║  Total words:           {analysis['total_words']:<40} ║
║  Unique words:          {analysis['unique_words']:<40} ║
║  Security keywords:     {sum(analysis['security_words'].values()):<40} ║
╠══════════════════════════════════════════════════════════════════╣
║  Output files:                                                   ║
║    - {OUTPUT_PREFIX}_frequency.png                                      ║
║    - {OUTPUT_PREFIX}_security.png                                       ║
║    - {OUTPUT_PREFIX}_wordcloud.png (if wordcloud installed)             ║
║    - {OUTPUT_PREFIX}.html                                               ║
╚══════════════════════════════════════════════════════════════════╝
    """)