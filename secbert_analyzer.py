#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secbert_analyzer.py - Semantic Security Analysis using SecBERT
==============================================================

Uses the 'jackaduma/SecBERT' model to analyze commit messages semantically.
It calculates a 'Security Relevance Score' by comparing commit messages
against a set of "Golden Security Sentences" (canonical threat descriptions).

Dependencies:
    pip install transformers torch scikit-learn numpy tqdm

Usage:
    python3 secbert_analyzer.py --input security_deltas.jsonl
"""

import json
import argparse
import numpy as np
import torch
from pathlib import Path
from typing import List, Dict
from transformers import AutoTokenizer, AutoModel
from tqdm import tqdm  # For progress bar

# =============================================================================
# CONFIGURATION
# =============================================================================

MODEL_NAME = "jackaduma/SecBERT"

# "Golden Sentences" representing high-criticality security fixes.
# We compare every commit message against these to calculate its score.
GOLDEN_VECTORS = [
    "Fix privilege escalation vulnerability in RBAC configuration",
    "Patch remote code execution flaw in API server",
    "Remediate hardcoded secret credential exposure",
    "Fix cross-site scripting XSS injection point",
    "Deny unauthenticated access to sensitive resource",
    "Restrict container capabilities to prevent breakout",
    "Update dependency to fix CVE critical vulnerability"
]


# =============================================================================
# SECBERT CLASS
# =============================================================================

class SecBERTAnalyzer:
    def __init__(self, model_name: str = MODEL_NAME):
        print(f"⏳ Loading SecBERT model: {model_name}...")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModel.from_pretrained(model_name)
            self.model.eval()  # Set to evaluation mode
            print("✅ Model loaded successfully.")
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            print("   Try running: pip install transformers torch")
            exit(1)

        # Pre-compute embeddings for our "Golden Sentences"
        print("⚙️  Computing baseline security vectors...")
        self.golden_embeddings = self._get_batch_embeddings(GOLDEN_VECTORS)

    def _get_batch_embeddings(self, texts: List[str]) -> np.ndarray:
        """
        Convert a list of texts into a matrix of embeddings.
        Returns: numpy array of shape (n_texts, hidden_size)
        """
        # Tokenize
        inputs = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=128,
            return_tensors="pt"
        )

        # Generate Embeddings
        with torch.no_grad():
            outputs = self.model(**inputs)

        # Mean Pooling: Average all token embeddings to get sentence representation
        #
        token_embeddings = outputs.last_hidden_state  # (batch, seq_len, hidden)
        attention_mask = inputs['attention_mask']  # (batch, seq_len)

        # Expand mask to match embedding shape
        mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()

        # Sum token embeddings and divide by valid token count
        sum_embeddings = torch.sum(token_embeddings * mask_expanded, 1)
        sum_mask = torch.clamp(mask_expanded.sum(1), min=1e-9)

        sentence_embeddings = sum_embeddings / sum_mask

        return sentence_embeddings.numpy()

    def score_message(self, message: str) -> float:
        if not message or not message.strip():
            return 0.0

        try:
            import torch
            import torch.nn.functional as F

            # Convert to tensors
            msg_embedding = torch.tensor(self._get_batch_embeddings([message]))
            golden_embeddings = torch.tensor(self.golden_embeddings)

            # Calculate Cosine Similarity (PyTorch requires matching dimensions, so we broadcast)
            # Unsqueeze to shape (1, 1, 768) vs (1, 7, 768)
            sim = F.cosine_similarity(msg_embedding.unsqueeze(1), golden_embeddings.unsqueeze(0), dim=2)

            return float(torch.max(sim))
        except Exception as e:
            print(f"⚠️ Error scoring message: {e}")
            return 0.0

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def process_file(input_file: str, output_file: str):
    analyzer = SecBERTAnalyzer()

    path = Path(input_file)
    if not path.exists():
        print(f"❌ Input file not found: {input_file}")
        return

    print(f"\n📂 Reading {input_file}...")
    data = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))

    print(f"🔍 Analyzing {len(data)} commits with SecBERT...")

    scored_data = []

    # Process with progress bar
    for entry in tqdm(data, desc="Scoring Commits", unit="msg"):
        msg = entry.get('commit_message', '') or entry.get('message', '')

        # Calculate Score
        score = analyzer.score_message(msg)

        # Assign Label based on score
        if score > 0.65:
            relevance = "HIGH"
        elif score > 0.45:
            relevance = "MEDIUM"
        else:
            relevance = "LOW"

        # Add analysis to the entry
        entry['secbert_score'] = round(score, 4)
        entry['secbert_relevance'] = relevance
        scored_data.append(entry)

    # Sort by Score (Highest Relevance First)
    scored_data.sort(key=lambda x: x['secbert_score'], reverse=True)

    # Save Results
    print(f"\n💾 Saving scored results to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in scored_data:
            f.write(json.dumps(entry) + '\n')

    # Print Top 5 Results
    print("\n🏆 Top 5 Most Relevant Security Commits found by SecBERT:")
    for i, entry in enumerate(scored_data[:5]):
        print(f"   [{entry['secbert_score']:.3f}] {entry.get('commit_message', '').splitlines()[0][:60]}...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SecBERT Security Analyzer')
    parser.add_argument('--input', default='security_deltas.jsonl', help='Input JSONL file')
    parser.add_argument('--output', default='security_deltas_scored.jsonl', help='Output JSONL file')

    args = parser.parse_args()

    process_file(args.input, args.output)

