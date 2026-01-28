import subprocess
import json
import tempfile
import os

def check_security_posture(code_content):
    """
    Analyzes code content using Semgrep to count security violations.
    """
    # Create a temporary file because Semgrep prefers file paths over raw strings
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode='w') as tmp:
        tmp.write(code_content)
        tmp_path = tmp.name

    try:
        # Run Semgrep using the official Kubernetes security policy
        result = subprocess.run(
            ["semgrep", "--config", "p/kubernetes", "--json", tmp_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return 0  # Return 0 if Semgrep fails to run

        data = json.loads(result.stdout)
        return len(data.get("results", []))
    except Exception as e:
        print(f"Semgrep Error: {e}")
        return 0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def extract_security_deltas(repo, IAC_KEYWORDS, limit=5):
    dataset = []
    commits = repo.get_commits()
    
    count = 0
    for commit in commits:
        msg = commit.commit.message.lower()
        # Filter for commits that likely change security posture.
        if any(key in msg for key in IAC_KEYWORDS):
            print(f"Analyzing security delta in commit: {commit.sha[:7]}")
            
            parent = commit.parents[0] if commit.parents else None
            if not parent: continue

            for file in commit.files:
                # Target IaC files like YAML (K8s) or Dockerfiles.
                if file.filename.endswith(('.yaml', '.yml', 'Dockerfile')):
                    try:
                        # Fetch 'Before' and 'After' states
                        vulnerable_code = repo.get_contents(file.filename, ref=parent.sha).decoded_content.decode()
                        fixed_code = repo.get_contents(file.filename, ref=commit.sha).decoded_content.decode()

                        dataset.append({
                            "commit_message": msg,
                            "file": file.filename,
                            "before": vulnerable_code,
                            "after": fixed_code,
                            "diff": file.patch
                        })
                    except Exception as e:
                        print(f"Error fetching delta for {file.filename}: {e}")

            count += 1
            if count >= limit: break
    return dataset


def semextract_security_deltas(repo, IAC_KEYWORDS, limit=5):
    """
    Enhanced extractor that uses Semgrep to quantify security posture changes.
    """
    dataset = []
    # We use a smaller per-page limit to be gentle on the GitHub API
    commits = repo.get_commits()

    count = 0
    for commit in commits:
        msg = commit.commit.message.lower()

        # Initial filter using keywords (Intent detection)
        if any(key in msg for key in IAC_KEYWORDS):
            print(f"🔍 Analyzing security delta in commit: {commit.sha[:7]}")

            parent = commit.parents[0] if commit.parents else None
            if not parent: continue

            for file in commit.files:
                # Target Infrastructure-as-Code files
                if file.filename.endswith(('.yaml', '.yml', 'Dockerfile')):
                    try:
                        # Fetch the raw code for both states
                        vulnerable_code = repo.get_contents(file.filename, ref=parent.sha).decoded_content.decode()
                        fixed_code = repo.get_contents(file.filename, ref=commit.sha).decoded_content.decode()

                        # --- SEMANTIC ANALYSIS START ---
                        # Use our library function to count findings
                        before_vuln_count = check_security_posture(vulnerable_code)
                        after_vuln_count = check_security_posture(fixed_code)

                        # Determine if the security posture actually changed
                        delta = after_vuln_count - before_vuln_count

                        if delta < 0:
                            status = "IMPROVED (Fix)"
                        elif delta > 0:
                            status = "REGRESSED (Vulnerability Introduced)"
                        else:
                            status = "NEUTRAL (No semantic change)"
                        # --- SEMANTIC ANALYSIS END ---

                        dataset.append({
                            "commit_sha": commit.sha,
                            "commit_message": msg,
                            "file": file.filename,
                            "before_vulns": before_vuln_count,
                            "after_vulns": after_vuln_count,
                            "posture_change": status,
                            "before_code": vulnerable_code,
                            "after_code": fixed_code,
                            "diff": file.patch
                        })
                        print(f"   ✅ {file.filename}: {status} ({before_vuln_count} -> {after_vuln_count})")

                    except Exception as e:
                        print(f"   ⚠️ Error fetching delta for {file.filename}: {e}")

            count += 1
            if count >= limit: break

    return dataset
    
def format_deltas(json, 
                  jsonl_file="security_deltas.jsonl"):
    """
    Load and display security deltas in a nice BEFORE/AFTER format.
    
    Usage:
        format_deltas()  # uses default file
        format_deltas("my_data.jsonl")
    """
    
    # Load the data
    deltas = []
    with open(jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                deltas.append(json.loads(line))
    
    print(f"\n{'='*70}")
    print(f"SECURITY DELTAS REPORT - {len(deltas)} entries")
    print(f"{'='*70}")
    
    for i, delta in enumerate(deltas, 1):
        # Get changed lines from the diff
        before_lines = []
        after_lines = []
        
        if delta.get('diff'):
            for line in delta['diff'].split('\n'):
                if line.startswith('-') and not line.startswith('---'):
                    before_lines.append(line[1:].strip())
                elif line.startswith('+') and not line.startswith('+++'):
                    after_lines.append(line[1:].strip())
        
        # Print formatted output
        print(f"\n{'─'*70}")
        print(f"[{i}] File: {delta.get('file', 'unknown')}")
        print(f"    Commit: {delta.get('commit_message', '')[:60]}")
        print()
        
        print("BEFORE:")
        if before_lines:
            for line in before_lines[:10]:  # Limit to 10 lines
                print(f"    {line[:65]}")
            if len(before_lines) > 10:
                print(f"    ... and {len(before_lines) - 10} more lines")
        else:
            print("    (no lines removed)")
        
        print()
        print("AFTER:")
        if after_lines:
            for line in after_lines[:10]:  # Limit to 10 lines
                print(f"    {line[:65]}")
            if len(after_lines) > 10:
                print(f"    ... and {len(after_lines) - 10} more lines")
        else:
            print("    (no lines added)")
        
        print(f"{'─'*70}")
    
    print(f"\n Formatted {len(deltas)} security deltas\n")
    
    
def format_deltas_html(json,
                       escape,
                       jsonl_file="security_deltas.jsonl", 
                       output_file="security_deltas.html"):
    """
    Load security deltas and save as a formatted HTML table.
    Optimized for large datasets (hundreds of entries).
    
    Features:
    - Search/filter functionality
    - Collapsible entries
    - Summary statistics
    - Keyboard navigation
    - Export filtered results
    
    Usage:
        format_deltas_html()  # uses default files
        format_deltas_html("my_data.jsonl", "my_report.html")
    """
    
    # Load the data
    deltas = []
    with open(jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                deltas.append(json.loads(line))
    
    # Calculate statistics
    file_types = {}
    for d in deltas:
        ext = d.get('file', '').split('.')[-1] if '.' in d.get('file', '') else 'unknown'
        file_types[ext] = file_types.get(ext, 0) + 1
    
    stats_html = ' | '.join([f"{ext}: {count}" for ext, count in sorted(file_types.items(), key=lambda x: -x[1])])
    
    # Build HTML
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Deltas Report</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        /* Header & Controls */
        .header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        h1 {
            color: #333;
            margin: 0 0 15px 0;
            font-size: 1.5em;
        }
        .controls {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        .search-box {
            flex: 1;
            min-width: 200px;
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        .search-box:focus {
            outline: none;
            border-color: #2196F3;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }
        .btn-primary {
            background: #2196F3;
            color: white;
        }
        .btn-primary:hover {
            background: #1976D2;
        }
        .btn-secondary {
            background: #e0e0e0;
            color: #333;
        }
        .btn-secondary:hover {
            background: #bdbdbd;
        }
        
        /* Stats */
        .stats {
            display: flex;
            gap: 20px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #eee;
            flex-wrap: wrap;
        }
        .stat-item {
            background: #e3f2fd;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 13px;
        }
        .stat-item.total {
            background: #4CAF50;
            color: white;
            font-weight: bold;
        }
        .stat-item.showing {
            background: #FF9800;
            color: white;
        }
        
        /* Delta Cards */
        .delta-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 10px;
            overflow: hidden;
        }
        .delta-card.hidden {
            display: none;
        }
        .delta-header {
            background: #2196F3;
            color: white;
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }
        .delta-header:hover {
            background: #1976D2;
        }
        .delta-header h3 {
            margin: 0;
            font-size: 14px;
            font-weight: 500;
        }
        .delta-header .meta {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        .delta-header .index {
            background: rgba(255,255,255,0.2);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .delta-header .toggle {
            font-size: 18px;
            transition: transform 0.2s;
        }
        .delta-card.collapsed .toggle {
            transform: rotate(-90deg);
        }
        .delta-header .commit-msg {
            font-size: 12px;
            opacity: 0.9;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        /* Collapsible Content */
        .delta-content {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 0;
            max-height: 2000px;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        .delta-card.collapsed .delta-content {
            max-height: 0;
        }
        .column {
            padding: 15px;
            border-right: 1px solid #eee;
            min-width: 0;
        }
        .column:last-child {
            border-right: none;
        }
        .column-header {
            font-weight: bold;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 2px solid #ddd;
            font-size: 13px;
        }
        .before .column-header {
            color: #c62828;
            border-bottom-color: #c62828;
        }
        .after .column-header {
            color: #2e7d32;
            border-bottom-color: #2e7d32;
        }
        .diff .column-header {
            color: #1565c0;
            border-bottom-color: #1565c0;
        }
        pre {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 11px;
            line-height: 1.4;
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
        }
        .before pre {
            background: #ffebee;
        }
        .after pre {
            background: #e8f5e9;
        }
        .diff pre {
            background: #e3f2fd;
        }
        .line-removed {
            background: #ffcdd2;
            display: block;
        }
        .line-added {
            background: #c8e6c9;
            display: block;
        }
        .empty {
            color: #999;
            font-style: italic;
        }
        .highlight {
            background: yellow;
            padding: 0 2px;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 13px;
        }
        
        /* Keyboard shortcuts hint */
        .shortcuts {
            font-size: 12px;
            color: #666;
            margin-top: 10px;
        }
        .shortcuts kbd {
            background: #eee;
            padding: 2px 6px;
            border-radius: 3px;
            border: 1px solid #ccc;
        }
        
        /* Responsive */
        @media (max-width: 1000px) {
            .delta-content {
                grid-template-columns: 1fr;
            }
            .column {
                border-right: none;
                border-bottom: 1px solid #eee;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Deltas Report</h1>
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" 
                   placeholder="Search files, commits, code... (Press / to focus)">
            <button class="btn btn-secondary" onclick="expandAll()">Expand All</button>
            <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
            <button class="btn btn-primary" onclick="exportVisible()">Export Visible</button>
        </div>
        <div class="stats">
            <span class="stat-item total">Total: """ + str(len(deltas)) + """</span>
            <span class="stat-item showing" id="showingCount">Showing: """ + str(len(deltas)) + """</span>
            <span class="stat-item">""" + stats_html + """</span>
        </div>
        <div class="shortcuts">
            <kbd>/</kbd> Search &nbsp;
            <kbd>Esc</kbd> Clear search &nbsp;
            <kbd>E</kbd> Expand all &nbsp;
            <kbd>C</kbd> Collapse all
        </div>
    </div>
    
    <div id="deltaContainer">
"""
    
    for i, delta in enumerate(deltas, 1):
        # Get changed lines from the diff
        before_lines = []
        after_lines = []
        
        if delta.get('diff'):
            for line in delta['diff'].split('\n'):
                if line.startswith('-') and not line.startswith('---'):
                    before_lines.append(line[1:])
                elif line.startswith('+') and not line.startswith('+++'):
                    after_lines.append(line[1:])
        
        # Escape HTML in content
        file_name = escape(delta.get('file', 'unknown'))
        commit_msg = escape(delta.get('commit_message', '').split('\n')[0][:80])
        
        # Format before content
        if before_lines:
            before_html = '\n'.join(f'<span class="line-removed">{escape(line)}</span>' for line in before_lines)
        else:
            before_html = '<span class="empty">(no lines removed)</span>'
        
        # Format after content
        if after_lines:
            after_html = '\n'.join(f'<span class="line-added">{escape(line)}</span>' for line in after_lines)
        else:
            after_html = '<span class="empty">(no lines added)</span>'
        
        # Format diff content
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
        diff_html = '\n'.join(diff_lines) if diff_lines else '<span class="empty">(no diff available)</span>'
        
        # Searchable data attribute (for filtering)
        search_data = escape(f"{file_name} {commit_msg} {' '.join(before_lines)} {' '.join(after_lines)}".lower())
        
        # Add card to HTML (collapsed by default for large datasets)
        collapsed_class = "collapsed" if len(deltas) > 20 else ""
        
        html += f"""
        <div class="delta-card {collapsed_class}" data-search="{search_data}">
            <div class="delta-header" onclick="toggleCard(this.parentElement)">
                <div>
                    <h3>{file_name}</h3>
                    <div class="commit-msg">{commit_msg}</div>
                </div>
                <div class="meta">
                    <span class="index">#{i}</span>
                    <span class="toggle">▼</span>
                </div>
            </div>
            <div class="delta-content">
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
"""
    
    html += """
    </div>
    
    <div class="footer">
        Generated from """ + str(len(deltas)) + """ security deltas
    </div>
    
    <script>
        // Toggle individual card
        function toggleCard(card) {
            card.classList.toggle('collapsed');
        }
        
        // Expand all visible cards
        function expandAll() {
            document.querySelectorAll('.delta-card:not(.hidden)').forEach(card => {
                card.classList.remove('collapsed');
            });
        }
        
        // Collapse all cards
        function collapseAll() {
            document.querySelectorAll('.delta-card').forEach(card => {
                card.classList.add('collapsed');
            });
        }
        
        // Search functionality
        const searchBox = document.getElementById('searchBox');
        const showingCount = document.getElementById('showingCount');
        
        searchBox.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            const cards = document.querySelectorAll('.delta-card');
            let visible = 0;
            
            cards.forEach(card => {
                const searchData = card.getAttribute('data-search');
                if (!query || searchData.includes(query)) {
                    card.classList.remove('hidden');
                    visible++;
                    // Auto-expand matching cards when searching
                    if (query) {
                        card.classList.remove('collapsed');
                    }
                } else {
                    card.classList.add('hidden');
                }
            });
            
            showingCount.textContent = 'Showing: ' + visible;
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Don't trigger if typing in search box
            if (document.activeElement === searchBox) {
                if (e.key === 'Escape') {
                    searchBox.value = '';
                    searchBox.dispatchEvent(new Event('input'));
                    searchBox.blur();
                }
                return;
            }
            
            switch(e.key) {
                case '/':
                    e.preventDefault();
                    searchBox.focus();
                    break;
                case 'e':
                case 'E':
                    expandAll();
                    break;
                case 'c':
                case 'C':
                    collapseAll();
                    break;
                case 'Escape':
                    searchBox.value = '';
                    searchBox.dispatchEvent(new Event('input'));
                    break;
            }
        });
        
        // Export visible entries as JSON
        function exportVisible() {
            const visibleCards = document.querySelectorAll('.delta-card:not(.hidden)');
            const data = [];
            
            visibleCards.forEach((card, index) => {
                const header = card.querySelector('h3').textContent;
                const commit = card.querySelector('.commit-msg').textContent;
                data.push({
                    index: index + 1,
                    file: header,
                    commit: commit
                });
            });
            
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'filtered_deltas.json';
            a.click();
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
"""
    
    # Save to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Saved HTML report to {output_file}")
    print(f"   Contains {len(deltas)} security deltas")
    print(f"   Features: Search, Collapse/Expand, Keyboard shortcuts, Export")
    
    return output_file
    