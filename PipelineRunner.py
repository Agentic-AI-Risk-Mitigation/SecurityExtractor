#!/usr/bin/env python3
"""PipelineRunner.py -- Master orchestrator for the lightweight security pipeline.

Stages
------
1. EXTRACT  -- Git delta extraction       -> security_results.jsonl
2. CHECKOV  -- Micro View (SAST)          -> checkov_results.json
3. THREAT   -- Macro View (Threat Model)  -> threat_model_results.json
4. COMPARE  -- Correlate Micro + Macro    -> comparison_results.json
5. REPORT   -- HTML dashboards            -> *.html

Settings are defined as constants below for easy exploration.
A snapshot of the active settings is saved to the output folder
as pipeline_settings.json alongside the results.
"""

import json
import logging
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import yaml

# ---------------------------------------------------------------------------
# Path setup 
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

# Add BASE_DIR to sys.path so we can import modules like CheckovScanner directly
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Imports from local modules
from SecurityDeltaExtractor import SecurityConfig, SecurityDeltaExtractor
from CheckovScanner import CheckovScanner  # noqa: E402
from PyTMGenerator import PyTMGenerator  # noqa: E402
from ExtractionReporter import ExtractionReporter  # noqa: E402
from ComparisonReporter import ComparisonReporter  # noqa: E402
from VulnerabilityComparator import VulnerabilityComparator  # noqa: E402

# ===================================================================
# PIPELINE SETTINGS -- edit these directly for quick exploration
# ===================================================================

# --- Repository ---
REPO_PATH = "data/kubernetes"
REPO_URL = "https://github.com/kubernetes/kubernetes"
BRANCH = "master"

# --- Extraction ---
SECURITY_CONFIG_PATH = "config/security_config.yaml"
EXTRACTION_LIMIT = 1000  # max security commits to scan
IAC_ONLY = True  # only extract deltas with IaC files
IAC_PATHS_ONLY = False  # restrict to known IaC directories
VERBOSE = True  # print per-commit progress

# --- Checkov (Micro View) ---
CHECKOV_TIMEOUT = 60  # seconds per file
CHECKOV_FRAMEWORK = "kubernetes"
CHECKOV_SKIP_NON_YAML = True  # skip files without apiVersion/kind
CHECKOV_WORKERS = 4  # parallel Checkov subprocesses (1 = sequential)

# --- Threat Model (Macro View) ---
THREAT_MODEL_SKIP_NON_K8S = True  # skip files without apiVersion/kind

# --- Comparison ---
WEIGHT_KEYWORD = 0.10
WEIGHT_CHECKOV = 0.45
WEIGHT_THREAT_MODEL = 0.45
SEVERITY_CRITICAL = 10
SEVERITY_HIGH = 5
SEVERITY_MEDIUM = 2
SEVERITY_LOW = 1
SEVERITY_INFO = 0
CSI_THRESHOLD = 0.30  # Commit of Security Interest threshold

# --- Attack Classes ---
ATTACK_CLASSES_PATH = "config/attack_classes.yaml"

# --- Output ---
OUTPUT_DIR = "output"
OUTPUT_EXTRACTION_JSONL = "security_results.jsonl"
OUTPUT_CHECKOV_JSON = "checkov_results.json"
OUTPUT_THREAT_MODEL_JSON = "threat_model_results.json"
OUTPUT_COMPARISON_JSON = "comparison_results.json"
OUTPUT_EXTRACTION_HTML = "git_security_deltas_report.html"
OUTPUT_COMPARISON_HTML = "comparison_report.html"
OUTPUT_SETTINGS_JSON = "pipeline_settings.json"

# --- Logging ---
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s %(message)s"


# ===================================================================
# Build the pipeline_cfg dict
# ===================================================================
def _build_pipeline_cfg() -> dict:
    """Assemble the pipeline config dict from the constants above."""
    return {
        "repository": {
            "path": REPO_PATH,
            "url": REPO_URL,
            "branch": BRANCH,
        },
        "extraction": {
            "config_path": SECURITY_CONFIG_PATH,
            "limit": EXTRACTION_LIMIT,
            "iac_only": IAC_ONLY,
            "iac_paths_only": IAC_PATHS_ONLY,
            "verbose": VERBOSE,
        },
        "checkov": {
            "timeout": CHECKOV_TIMEOUT,
            "framework": CHECKOV_FRAMEWORK,
            "skip_non_yaml": CHECKOV_SKIP_NON_YAML,
            "workers": CHECKOV_WORKERS,
        },
        "threat_model": {
            "skip_non_k8s": THREAT_MODEL_SKIP_NON_K8S,
        },
        "comparison": {
            "weights": {
                "keyword": WEIGHT_KEYWORD,
                "checkov": WEIGHT_CHECKOV,
                "threat_model": WEIGHT_THREAT_MODEL,
            },
            "severity_weights": {
                "CRITICAL": SEVERITY_CRITICAL,
                "HIGH": SEVERITY_HIGH,
                "MEDIUM": SEVERITY_MEDIUM,
                "LOW": SEVERITY_LOW,
                "INFO": SEVERITY_INFO,
            },
            "csi_threshold": CSI_THRESHOLD,
        },
        "attack_classes": {
            "config_path": ATTACK_CLASSES_PATH,
        },
        "output": {
            "directory": OUTPUT_DIR,
            "extraction_jsonl": OUTPUT_EXTRACTION_JSONL,
            "checkov_json": OUTPUT_CHECKOV_JSON,
            "threat_model_json": OUTPUT_THREAT_MODEL_JSON,
            "comparison_json": OUTPUT_COMPARISON_JSON,
            "extraction_report_html": OUTPUT_EXTRACTION_HTML,
            "comparison_report_html": OUTPUT_COMPARISON_HTML,
        },
        "logging": {
            "level": LOG_LEVEL,
            "format": LOG_FORMAT,
        },
    }


def _load_yaml(path: Path) -> dict:
    """Load and return a YAML file as a dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _save_settings(pipeline_cfg: dict, output_path: str) -> None:
    """Save the active pipeline settings alongside the results."""
    snapshot = {
        "saved_at": datetime.now().isoformat(),
        "pipeline_settings": pipeline_cfg,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    """Helper to load JSONL file for the comparator step."""
    data = []
    p = Path(path)
    if not p.exists():
        logging.warning(f"File not found for loading: {path}")
        return []

    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return data


def main() -> None:
    # Setup Logging
    logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
    logger = logging.getLogger(__name__)

    # Build config from constants
    pipeline_cfg = _build_pipeline_cfg()

    # Load attack classes YAML
    ac_cfg = _load_yaml(
        BASE_DIR / pipeline_cfg["attack_classes"]["config_path"]
    )
    sec_cfg_path = str(
        BASE_DIR / pipeline_cfg["extraction"]["config_path"]
    )

    # Resolve paths
    repo_path = str(BASE_DIR / pipeline_cfg["repository"]["path"])
    repo_url = pipeline_cfg["repository"]["url"]
    branch = pipeline_cfg["repository"]["branch"]
    limit = pipeline_cfg["extraction"]["limit"]

    output_dir = BASE_DIR / pipeline_cfg["output"]["directory"]
    output_dir.mkdir(parents=True, exist_ok=True)

    out = pipeline_cfg["output"]
    jsonl_output = str(output_dir / out["extraction_jsonl"])
    checkov_output = str(output_dir / out["checkov_json"])
    threat_output = str(output_dir / out["threat_model_json"])
    comparison_output = str(output_dir / out["comparison_json"])
    extraction_html = str(output_dir / out["extraction_report_html"])
    comparison_html = str(output_dir / out["comparison_report_html"])
    settings_output = str(output_dir / OUTPUT_SETTINGS_JSON)

    _save_settings(pipeline_cfg, settings_output)

    try:
        # ---------------------------------------------------------
        # Stage 1: EXTRACT: Git delta extraction
        # ---------------------------------------------------------
        logger.info("--- Stage 1: Extraction ---")
        ext_cfg = pipeline_cfg["extraction"]
        sec_config = SecurityConfig.from_yaml(sec_cfg_path)
        engine = SecurityDeltaExtractor(repo_path, sec_config)

        # Run extraction
        deltas = engine.run(
            limit=limit,
            branch=branch,
            iac_only=ext_cfg.get("iac_only", True),
            iac_paths_only=ext_cfg.get("iac_paths_only", False),
            verbose=ext_cfg.get("verbose", True),
        )

        if not deltas:
            logger.warning("No deltas found. Pipeline stopping.")
            return

        # Output: security_results.jsonl
        engine.save_jsonl(deltas, jsonl_output)

        # ---------------------------------------------------------
        # Stage 2: CHECKOV: Micro View (SAST)
        # ---------------------------------------------------------
        logger.info("--- Stage 2: Checkov Scanning ---")
        # Input: Explicitly reads security_results.jsonl
        scanner = CheckovScanner(
            pipeline_cfg,
            attack_classes_cfg=ac_cfg,
            config_dir=str(BASE_DIR / "config"),
        )
        checkov_results = scanner.scan_deltas_from_file(jsonl_output)

        # Output: checkov_results.json
        scanner.save_json(checkov_results, checkov_output)

        # ---------------------------------------------------------
        # Stage 3: THREAT MODEL: Macro View
        # ---------------------------------------------------------
        logger.info("--- Stage 3: Threat Modeling ---")
        # Input: Explicitly reads security_results.jsonl
        modeler = PyTMGenerator(
            pipeline_cfg,
            config_dir=str(BASE_DIR / "config"),
        )
        threat_results = modeler.model_deltas_from_file(jsonl_output)

        # Output: threat_model_results.json
        modeler.save_json(threat_results, threat_output)

        # ---------------------------------------------------------
        # Stage 4: COMPARE: Correlate Micro + Macro
        # ---------------------------------------------------------
        logger.info("--- Stage 4: Comparison ---")

        # Input: Explicitly load all three input files from disk
        # (simulates a clean hand-off between pipeline stages)
        logger.info(f"Loading inputs for comparison from {output_dir}...")
        deltas_from_file = _load_jsonl(jsonl_output)

        with open(checkov_output, "r", encoding="utf-8") as f:
            ck_data = json.load(f)

        with open(threat_output, "r", encoding="utf-8") as f:
            tm_data = json.load(f)

        comparator = VulnerabilityComparator(pipeline_cfg)
        comparison_results = comparator.compare(deltas_from_file, ck_data, tm_data)

        # Output: comparison_results.json
        comparator.save_json(comparison_results, comparison_output)

        # ---------------------------------------------------------
        # Stage 5: REPORT: Generate HTML reports
        # ---------------------------------------------------------
        logger.info("--- Stage 5: Reporting ---")

        # Report 1: Extraction Table
        # Input: Explicitly load from security_results.jsonl
        ext_reporter = ExtractionReporter(extraction_html, repo_url)
        ext_reporter.generate(jsonl_file=jsonl_output)

        # Report 2: Comparison Dashboard
        # Input: Explicitly load from comparison_results.json
        comp_reporter = ComparisonReporter(
            comparison_html, repo_url, ac_cfg
        )
        comp_reporter.generate(json_file=comparison_output)

        # ---------------------------------------------------------
        # Final Summary
        # ---------------------------------------------------------
        regressions = sum(
            1 for r in comparison_results
            if r.posture_direction == "regression"
        )
        improvements = sum(
            1 for r in comparison_results
            if r.posture_direction == "improvement"
        )
        csi_count = sum(
            1 for r in comparison_results if r.is_csi
        )
        macro_only = sum(
            1 for r in comparison_results if r.macro_only
        )

        logger.info("Pipeline completed successfully.")
        logger.info(f"Regressions: {regressions}, Improvements: {improvements}")
        logger.info(f"CSI Commits: {csi_count}, Macro-only findings: {macro_only}")
        logger.info(f"Reports saved to: {output_dir}")

    except Exception as e:
        logger.exception("Pipeline failed with error:")
        raise


if __name__ == "__main__":
    main()