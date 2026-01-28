# Initial script to fetch security information.
import os
import json
from github import Github
from dotenv import load_dotenv
from html import escape
import funclib as func
import semfunclib as semfunc

load_dotenv()

token = os.getenv('GITHUB_TOKEN')
g = Github(token)

rate_limit = g.get_rate_limit()
core = rate_limit.resources.core

print(token)
print(f"Token Loaded from .env: {'Yes' if token else 'No'}")
print(f"Limit: {core.limit}")
print(f"Remaining: {core.remaining}")
print(f"Reset Time (UTC): {core.reset}")

repo = g.get_repo("kubernetes/kubernetes")

# Define "Security Posture" signals 
IAC_KEYWORDS = ["security",
                "fix",
                "vuln",
                "rbac",
                "secret",
                "privileged"]

# =============================================================================
# Main Execution
# =============================================================================
if __name__ == "__main__":
    # Execute and Save
    data = func.extract_security_deltas(repo, IAC_KEYWORDS, limit=100)
    with open("security_deltas.jsonl", "w") as f:
        for entry in data:
            f.write(json.dumps(entry) + "\n")

    print(f"Successfully saved {len(data)} deltas to security_deltas.jsonl")
    
    # Format and display the results
    func.format_deltas(json)   
    
    import sys
    if len(sys.argv) > 1:
        func.format_deltas_html(json, escape, sys.argv[1])
    else:
        func.format_deltas_html(json, escape)

    
    