import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# 1. Load the Data
file_path = 'security_deltas_scored.jsonl'
print(f"📂 Loading {file_path}...")

# Read JSONL file into a Pandas DataFrame
df = pd.read_json(file_path, lines=True)

# Basic cleanup: Ensure we have numeric scores
df['secbert_score'] = pd.to_numeric(df['secbert_score'], errors='coerce')

# Set the visual style
sns.set_theme(style="whitegrid")

# ==============================================================================
# PLOT 1: The "relevance" Distribution (Histogram)
# ==============================================================================
# This tells you if SecBERT is confident (bimodal) or confused (flat).
plt.figure(figsize=(10, 6))
sns.histplot(data=df, x='secbert_score', bins=20, kde=True, color='teal')
plt.title('Distribution of SecBERT Security Scores', fontsize=16)
plt.xlabel('Security Relevance Score (0.0 - 1.0)', fontsize=12)
plt.ylabel('Count of Commits', fontsize=12)
plt.axvline(x=0.65, color='red', linestyle='--', label='High Relevance Threshold (0.65)')
plt.legend()
plt.savefig('viz_score_distribution.png')
print("✅ Saved viz_score_distribution.png")

# ==============================================================================
# PLOT 2: Validation Check (Box Plot)
# ==============================================================================
# Does a "Semgrep Fix" actually correlate with a "High SecBERT Score"?
# We compare the 'posture_change' (from Semgrep) vs 'secbert_score'.

if 'posture_change' in df.columns:
    plt.figure(figsize=(12, 6))

    # Create a box plot sorted by median score
    order = df.groupby('posture_change')['secbert_score'].median().sort_values(ascending=False).index

    sns.boxplot(data=df, x='posture_change', y='secbert_score', order=order, palette="viridis")
    plt.title('SecBERT Score by Semgrep Posture Change', fontsize=16)
    plt.xticks(rotation=45)
    plt.xlabel('Semgrep Detected Change', fontsize=12)
    plt.ylabel('SecBERT Similarity Score', fontsize=12)
    plt.tight_layout()
    plt.savefig('viz_validation_boxplot.png')
    print("✅ Saved viz_validation_boxplot.png")
else:
    print("⚠️ 'posture_change' field not found. Skipping Box Plot.")

# ==============================================================================
# PLOT 3: High vs Low Relevance Count (Bar Chart)
# ==============================================================================
plt.figure(figsize=(8, 6))
sns.countplot(data=df, x='secbert_relevance', order=['HIGH', 'MEDIUM', 'LOW'], palette="magma")
plt.title('Count of Commits by Relevance Category', fontsize=16)
plt.xlabel('Relevance Label', fontsize=12)
plt.ylabel('Number of Commits', fontsize=12)
plt.savefig('viz_relevance_counts.png')
print("✅ Saved viz_relevance_counts.png")