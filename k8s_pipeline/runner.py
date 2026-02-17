#!/usr/bin/env python3
"""PipelineRunner.py -- Master orchestrator for the lightweight security pipeline.

Stages
------
1. EXTRACT  -- Git delta extraction       -> security_results.jsonl
2. CHECKOV  -- Micro View (SAST)          -> checkov_results.json
3. THREAT   -- Macro View (Threat Model)  -> threat_model_results.json
                                             full_pytm_results.json
4. COMPARE  -- Correlate Micro + Macro    -> comparison_results.json
5. EXPLAIN  -- LLM explanation (OpenRouter)-> llm_explanations.json
6. REPORT   -- HTML dashboards            -> comparison_report.html
                                             llm_explainer_report.html
7. OVERVIEW -- Overview + file viewers     -> pipeline_overview.html
                                             output/docs/*.html
8. PUBLISH  -- GitHub Pages site prep      -> docs/index.html
9. ARCHIVE  -- Run artifacts snapshot      -> output/<timestamp>/

Settings are defined as constants below for easy exploration.
A snapshot of the active settings is saved to the output folder
as pipeline_settings.json alongside the results.
"""

import json
import logging
import shutil
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import yaml

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

from SecurityDeltaExtractor import SecurityConfig, SecurityDeltaExtractor
from CheckovScanner import CheckovScanner  # noqa: E402
from DeltaThreatModelDiffGenerator import (  # noqa: E402
    DeltaThreatModelDiffGenerator,
)
from FullPyTMGenerator import FullPyTMGenerator  # noqa: E402
from LLMExplainer import LLMExplainer  # noqa: E402
from ExtractionReporter import ExtractionReporter  # noqa: E402
from ComparisonReporter import ComparisonReporter  # noqa: E402
from LLMExplainerReporter import LLMExplainerReporter  # noqa: E402
from PipelineOverviewGenerator import PipelineOverviewGenerator  # noqa: E402
from GitHubPagesPublisher import GitHubPagesPublisher  # noqa: E402
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
EXTRACTION_LIMIT = 1500  # max security commits to scan
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

# --- LLM Explainer (OpenRouter) ---
# Single source of truth is config/llm_explainer_config.yaml.
LLM_EXPLAINER_CONFIG_PATH = "config/llm_explainer_config.yaml"

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

# --- GitHub Pages ---
GHPAGES_ENABLED = True
GHPAGES_CONFIG_PATH = "config/github_pages_config.yaml"
GHPAGES_SITE_DIR = "docs"
GHPAGES_INDEX_SOURCE = "pipeline_overview.html"
GHPAGES_INCLUDE_FILES = [
    "pipeline_overview.html",
    "comparison_report.html",
    "git_security_deltas_report.html",
    "llm_explainer_report.html",
]
GHPAGES_INCLUDE_DIRS = ["docs"]
GHPAGES_VIEWER_MAX_LINES = 1000
GHPAGES_VIEWER_MAX_LINE_CHARS = 4000
GHPAGES_STRICT_REQUIRED_ARTIFACTS = True
GHPAGES_REQUIRED_ARTIFACTS = [
    "pipeline_overview.html",
    "comparison_report.html",
    "git_security_deltas_report.html",
    "llm_explainer_report.html",
    "docs",
]
GHPAGES_AUTO_COMMIT = True
GHPAGES_AUTO_PUSH = True
GHPAGES_COMMIT_MESSAGE = "chore(pages): update security pipeline site artifacts"
GHPAGES_BRANCH = "main"

# --- Attack Classes ---
ATTACK_CLASSES_PATH = "config/attack_classes.yaml"

# --- Output ---
OUTPUT_DIR = "output"
OUTPUT_EXTRACTION_JSONL = "security_results.jsonl"
OUTPUT_CHECKOV_JSON = "checkov_results.json"
OUTPUT_THREAT_MODEL_JSON = "threat_model_results.json"
OUTPUT_FULL_PYTM_JSON = "full_pytm_results.json"
OUTPUT_COMPARISON_JSON = "comparison_results.json"
OUTPUT_LLM_EXPLANATIONS_JSON = "llm_explanations.json"
OUTPUT_EXTRACTION_HTML = "git_security_deltas_report.html"
OUTPUT_COMPARISON_HTML = "comparison_report.html"
OUTPUT_LLM_EXPLAINER_HTML = "llm_explainer_report.html"
OUTPUT_PIPELINE_OVERVIEW_HTML = "pipeline_overview.html"
OUTPUT_SETTINGS_JSON = "pipeline_settings.json"
OUTPUT_LOGS_DIR = "logs"

# --- Logging ---
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s %(message)s"

# --- Execution window ---
START_STAGE = 1
END_STAGE = 9

STAGE_MIN = 1
STAGE_MAX = 9
STAGE_NAMES = {
    1: "Extraction",
    2: "Checkov Scanning",
    3: "Threat Modeling (Delta + Full)",
    4: "Comparison",
    5: "LLM Explainer",
    6: "Reporting",
    7: "Pipeline Overview Generation",
    8: "GitHub Pages Publish Prep",
    9: "Archiving Outputs",
}


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
        "llm_explainer": {
            "config_path": LLM_EXPLAINER_CONFIG_PATH,
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
        "github_pages": {
            "enabled": GHPAGES_ENABLED,
            "config_path": GHPAGES_CONFIG_PATH,
            "site_dir": GHPAGES_SITE_DIR,
            "index_source": GHPAGES_INDEX_SOURCE,
            "include_files": GHPAGES_INCLUDE_FILES,
            "include_dirs": GHPAGES_INCLUDE_DIRS,
            "viewer_max_lines": GHPAGES_VIEWER_MAX_LINES,
            "viewer_max_line_chars": GHPAGES_VIEWER_MAX_LINE_CHARS,
            "strict_required_artifacts": GHPAGES_STRICT_REQUIRED_ARTIFACTS,
            "required_artifacts": GHPAGES_REQUIRED_ARTIFACTS,
            "auto_commit": GHPAGES_AUTO_COMMIT,
            "auto_push": GHPAGES_AUTO_PUSH,
            "commit_message": GHPAGES_COMMIT_MESSAGE,
            "branch": GHPAGES_BRANCH,
        },
        "attack_classes": {
            "config_path": ATTACK_CLASSES_PATH,
        },
        "output": {
            "directory": OUTPUT_DIR,
            "extraction_jsonl": OUTPUT_EXTRACTION_JSONL,
            "checkov_json": OUTPUT_CHECKOV_JSON,
            "threat_model_json": OUTPUT_THREAT_MODEL_JSON,
            "full_pytm_json": OUTPUT_FULL_PYTM_JSON,
            "comparison_json": OUTPUT_COMPARISON_JSON,
            "llm_explanations_json": OUTPUT_LLM_EXPLANATIONS_JSON,
            "extraction_report_html": OUTPUT_EXTRACTION_HTML,
            "comparison_report_html": OUTPUT_COMPARISON_HTML,
            "llm_explainer_report_html": OUTPUT_LLM_EXPLAINER_HTML,
            "pipeline_overview_html": OUTPUT_PIPELINE_OVERVIEW_HTML,
        },
        "logging": {
            "level": LOG_LEVEL,
            "format": LOG_FORMAT,
        },
        "execution": {
            "start_stage": START_STAGE,
            "end_stage": END_STAGE,
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


def _merge_llm_explainer_cfg(pipeline_cfg: dict) -> None:
    """Load llm_explainer settings from YAML config file (required)."""
    llm_cfg = pipeline_cfg.get("llm_explainer", {})
    cfg_path_rel = llm_cfg.get("config_path", LLM_EXPLAINER_CONFIG_PATH)
    cfg_path = BASE_DIR / cfg_path_rel
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Missing LLM config file: {cfg_path}. "
            "Create it or set llm_explainer.config_path accordingly."
        )

    loaded = _load_yaml(cfg_path)
    # Support either top-level keys or nested under `llm_explainer:`
    overrides = loaded.get("llm_explainer", loaded)
    if not isinstance(overrides, dict) or not overrides:
        raise ValueError(
            f"Invalid llm_explainer config in {cfg_path}: expected non-empty mapping."
        )

    merged = {"config_path": cfg_path_rel}
    merged.update(overrides)
    pipeline_cfg["llm_explainer"] = merged


def _merge_github_pages_cfg(pipeline_cfg: dict) -> None:
    """Overlay github_pages settings from YAML config file if present."""
    gh_cfg = pipeline_cfg.get("github_pages", {})
    cfg_path = BASE_DIR / gh_cfg.get("config_path", GHPAGES_CONFIG_PATH)
    if not cfg_path.exists():
        return

    loaded = _load_yaml(cfg_path)
    overrides = loaded.get("github_pages", loaded)
    if not isinstance(overrides, dict):
        return

    for key, value in overrides.items():
        gh_cfg[key] = value


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    """Helper to load JSONL file for the comparator step.

    Notes:
      - This returns a list of dicts (JSON objects) as written by engine.save_jsonl().
      - If you previously passed dataclass objects around, ensure downstream steps
        accept dicts (or add a conversion layer here).
    """
    data: List[Dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        logging.warning(f"File not found for loading: {path}")
        return []

    with open(p, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    data.append(obj)
                else:
                    logging.warning(f"JSONL line {idx} is not an object; skipping.")
            except json.JSONDecodeError as e:
                logging.warning(f"JSON decode error in {p.name}:{idx}: {e}")
    return data


def _load_json(path: str, default: Any) -> Any:
    """Load JSON file, returning default on missing/unreadable content."""
    p = Path(path)
    if not p.exists():
        return default
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as exc:
        logging.warning("Failed to load JSON from %s: %s", path, exc)
        return default


def _parse_args() -> argparse.Namespace:
    """Parse optional CLI stage range controls."""
    parser = argparse.ArgumentParser(
        description="Run the Security Extractor pipeline."
    )
    parser.add_argument(
        "--start-stage",
        type=int,
        choices=range(STAGE_MIN, STAGE_MAX + 1),
        help=f"Start from this stage ({STAGE_MIN}-{STAGE_MAX}).",
    )
    parser.add_argument(
        "--end-stage",
        type=int,
        choices=range(STAGE_MIN, STAGE_MAX + 1),
        help=f"Stop after this stage ({STAGE_MIN}-{STAGE_MAX}).",
    )
    return parser.parse_args()


def _should_run_stage(stage: int, start_stage: int, end_stage: int) -> bool:
    return start_stage <= stage <= end_stage


def _ensure_artifacts(paths: List[str], reason: str) -> None:
    """Raise with clear guidance when required prior-stage artifacts are missing."""
    missing = [p for p in paths if not Path(p).exists()]
    if not missing:
        return
    missing_list = ", ".join(missing)
    raise FileNotFoundError(
        f"{reason} requires existing artifact(s): {missing_list}. "
        "Run earlier stages first or choose an earlier --start-stage."
    )


def _archive_outputs(
    output_dir: Path,
    files: List[str],
    run_timestamp: str,
) -> Path:
    """Copy pipeline artifacts into an output subfolder for this run."""
    archive_dir = output_dir / run_timestamp
    archive_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for file_path in files:
        src = Path(file_path)
        if not src.exists():
            logging.warning(f"Skipping missing output for archive: {src}")
            continue
        shutil.copy2(src, archive_dir / src.name)
        copied += 1

    logging.info(f"Archived {copied} output files to: {archive_dir}")
    return archive_dir


class _LoggerNamePrefixFilter(logging.Filter):
    """Allow log records only for exact logger names or child loggers."""

    def __init__(self, logger_names: List[str]) -> None:
        super().__init__()
        self.logger_names = tuple(logger_names)

    def filter(self, record: logging.LogRecord) -> bool:
        for logger_name in self.logger_names:
            if record.name == logger_name:
                return True
            if record.name.startswith(f"{logger_name}."):
                return True
        return False


def _setup_logging(
    output_dir: Path,
    run_timestamp: str,
    level_name: str,
    log_format: str,
) -> Dict[str, str]:
    """Configure console + per-run file logging.

    Returns a map of logical log names to file paths, including:
    - log_dir
    - pipeline_full
    - pipeline_runner
    - security_extraction
    - checkov
    - delta_threat_model
    - full_pytm
    - comparison
    - reporting
    """
    log_dir = output_dir / OUTPUT_LOGS_DIR / run_timestamp
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, level_name.upper(), logging.INFO)
    formatter = logging.Formatter(log_format)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Reset handlers so repeated runs in the same process don't duplicate logs.
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    log_files: Dict[str, str] = {"log_dir": str(log_dir)}

    full_log_path = log_dir / "pipeline_full.log"
    full_handler = logging.FileHandler(full_log_path, encoding="utf-8")
    full_handler.setLevel(level)
    full_handler.setFormatter(formatter)
    root_logger.addHandler(full_handler)
    log_files["pipeline_full"] = str(full_log_path)

    component_filters: Dict[str, List[str]] = {
        "pipeline_runner": ["__main__", "PipelineRunner"],
        "security_extraction": ["SecurityDeltaExtractor"],
        "checkov": ["CheckovScanner"],
        "delta_threat_model": ["DeltaThreatModelDiffGenerator"],
        "full_pytm": ["FullPyTMGenerator"],
        "llm_explainer": ["LLMExplainer"],
        "github_pages": ["GitHubPagesPublisher"],
        "overview_generation": ["PipelineOverviewGenerator"],
        "comparison": ["VulnerabilityComparator"],
        "reporting": [
            "ExtractionReporter",
            "ComparisonReporter",
            "LLMExplainerReporter",
        ],
    }

    for log_name, logger_names in component_filters.items():
        path = log_dir / f"{log_name}.log"
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(level)
        handler.setFormatter(formatter)
        handler.addFilter(_LoggerNamePrefixFilter(logger_names))
        root_logger.addHandler(handler)
        log_files[log_name] = str(path)

    return log_files


def main() -> None:
    args = _parse_args()

    # Build config from constants
    pipeline_cfg = _build_pipeline_cfg()
    _merge_llm_explainer_cfg(pipeline_cfg)
    _merge_github_pages_cfg(pipeline_cfg)

    exec_cfg = pipeline_cfg.get("execution", {})
    start_stage = int(exec_cfg.get("start_stage", START_STAGE))
    end_stage = int(exec_cfg.get("end_stage", END_STAGE))
    if args.start_stage is not None:
        start_stage = args.start_stage
    if args.end_stage is not None:
        end_stage = args.end_stage
    if start_stage > end_stage:
        raise ValueError(
            f"Invalid stage window: start_stage={start_stage} > end_stage={end_stage}."
        )
    if start_stage < STAGE_MIN or end_stage > STAGE_MAX:
        raise ValueError(
            f"Stage window must stay within {STAGE_MIN}-{STAGE_MAX}."
        )
    pipeline_cfg["execution"] = {
        "start_stage": start_stage,
        "end_stage": end_stage,
    }

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
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_files = _setup_logging(
        output_dir=output_dir,
        run_timestamp=run_timestamp,
        level_name=LOG_LEVEL,
        log_format=LOG_FORMAT,
    )
    logger = logging.getLogger(__name__)
    logger.info("Run log directory: %s", log_files["log_dir"])
    logger.info(
        "Execution window: stages %s..%s",
        start_stage,
        end_stage,
    )
    run_stage = {
        stage: _should_run_stage(stage, start_stage, end_stage)
        for stage in range(STAGE_MIN, STAGE_MAX + 1)
    }

    out = pipeline_cfg["output"]
    jsonl_output = str(output_dir / out["extraction_jsonl"])
    checkov_output = str(output_dir / out["checkov_json"])
    threat_output = str(output_dir / out["threat_model_json"])
    full_pytm_output = str(output_dir / out["full_pytm_json"])
    comparison_output = str(output_dir / out["comparison_json"])
    llm_output = str(output_dir / out["llm_explanations_json"])
    extraction_html = str(output_dir / out["extraction_report_html"])
    comparison_html = str(output_dir / out["comparison_report_html"])
    llm_explainer_html = str(output_dir / out["llm_explainer_report_html"])
    pipeline_overview_html = str(output_dir / out["pipeline_overview_html"])
    settings_output = str(output_dir / OUTPUT_SETTINGS_JSON)
    pipeline_cfg["logging"]["run_log_dir"] = log_files["log_dir"]
    pipeline_cfg["logging"]["log_files"] = {
        k: v for k, v in log_files.items() if k != "log_dir"
    }

    _save_settings(pipeline_cfg, settings_output)

    try:
        comparison_results: List[Any] = []
        full_pytm_results: Dict[str, Any] = {}
        llm_result: Dict[str, Any] = {}
        overview_result: Dict[str, Any] = {}
        gh_pages_result: Dict[str, Any] = {}

        # ---------------------------------------------------------
        # Stage 1: EXTRACT: Git delta extraction
        # ---------------------------------------------------------
        if run_stage[1]:
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
        else:
            logger.info("--- Stage 1: skipped ---")
            if any(run_stage[s] for s in (2, 3, 4, 5, 6)):
                _ensure_artifacts(
                    [jsonl_output],
                    "Later stages (2-6)",
                )

        # ---------------------------------------------------------
        # Stage 2: CHECKOV: Micro View (SAST)
        # ---------------------------------------------------------
        if run_stage[2]:
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
        else:
            logger.info("--- Stage 2: skipped ---")
            if run_stage[4]:
                _ensure_artifacts(
                    [checkov_output],
                    "Stage 4",
                )

        # ---------------------------------------------------------
        # Stage 3A: THREAT MODEL (Delta): Macro View for per-delta comparison
        # ---------------------------------------------------------
        if run_stage[3]:
            logger.info("--- Stage 3A: Threat Modeling (Delta) ---")
            # Input: Explicitly reads security_results.jsonl
            modeler = DeltaThreatModelDiffGenerator(
                pipeline_cfg,
                config_dir=str(BASE_DIR / "config"),
            )
            threat_results = modeler.model_deltas_from_file(jsonl_output)

            # Output: threat_model_results.json
            modeler.save_json(threat_results, threat_output)

            # ---------------------------------------------------------
            # Stage 3B: THREAT MODEL (Full): Native pytm on repository snapshot
            # ---------------------------------------------------------
            logger.info("--- Stage 3B: Threat Modeling (Full Native PyTM) ---")
            full_modeler = FullPyTMGenerator(repo_path=repo_path)
            full_pytm_results = full_modeler.run()
            full_modeler.save_json(full_pytm_results, full_pytm_output)
        else:
            logger.info("--- Stage 3: skipped ---")
            if run_stage[4]:
                _ensure_artifacts(
                    [threat_output, full_pytm_output],
                    "Stage 4",
                )
            elif any(run_stage[s] for s in (5, 6)):
                _ensure_artifacts(
                    [full_pytm_output],
                    "Stages 5-6",
                )

        # ---------------------------------------------------------
        # Stage 4: COMPARE: Correlate Micro + Macro
        # ---------------------------------------------------------
        if run_stage[4]:
            logger.info("--- Stage 4: Comparison ---")

            # Input: Explicitly load all three input files from disk
            # (simulates a clean hand-off between pipeline stages)
            logger.info(f"Loading inputs for comparison from {output_dir}...")
            deltas_from_file = _load_jsonl(jsonl_output)

            if not deltas_from_file:
                logger.error("No deltas loaded from JSONL (unexpected). Aborting comparison.")
                return

            with open(checkov_output, "r", encoding="utf-8") as f:
                ck_data = json.load(f)

            with open(threat_output, "r", encoding="utf-8") as f:
                tm_data = json.load(f)

            comparator = VulnerabilityComparator(pipeline_cfg)
            comparison_results = comparator.compare(deltas_from_file, ck_data, tm_data)

            # Output: comparison_results.json
            comparator.save_json(comparison_results, comparison_output)
        else:
            logger.info("--- Stage 4: skipped ---")
            if any(run_stage[s] for s in (5, 6)):
                _ensure_artifacts(
                    [comparison_output],
                    "Stages 5-6",
                )

        # ---------------------------------------------------------
        # Stage 5: EXPLAIN: LLM explanation over top findings
        # ---------------------------------------------------------
        if run_stage[5]:
            logger.info("--- Stage 5: LLM Explainer ---")
            llm_cfg = pipeline_cfg.get("llm_explainer", {})
            if llm_cfg.get("enabled", True):
                llm_explainer = LLMExplainer(
                    pipeline_cfg,
                    prompt_template_path=str(BASE_DIR / llm_cfg.get(
                        "prompt_template", "config/llm_prompt_template.txt"
                    )),
                )
                llm_result = llm_explainer.explain_from_files(
                    comparison_json_file=comparison_output,
                    extraction_jsonl_file=jsonl_output,
                    full_pytm_json_file=full_pytm_output,
                )
            else:
                llm_result = {
                    "status": "skipped",
                    "generated_at": datetime.now().isoformat(),
                    "limitations": ["llm_explainer.enabled is false"],
                    "items": [],
                }
            LLMExplainer.save_json(llm_result, llm_output)
        else:
            logger.info("--- Stage 5: skipped ---")
            if run_stage[6]:
                _ensure_artifacts(
                    [llm_output],
                    "Stage 6",
                )

        # ---------------------------------------------------------
        # Stage 6: REPORT: Generate HTML reports
        # ---------------------------------------------------------
        if run_stage[6]:
            logger.info("--- Stage 6: Reporting ---")

            # Report 1: Extraction Table
            # Input: Explicitly load from security_results.jsonl
            ext_reporter = ExtractionReporter(extraction_html, repo_url)
            ext_reporter.generate(jsonl_file=jsonl_output)

            # Report 2: Comparison Dashboard
            # Input: Explicitly load from comparison_results.json
            comp_reporter = ComparisonReporter(
                comparison_html, repo_url, ac_cfg
            )
            comp_reporter.generate(
                json_file=comparison_output,
                full_pytm_json_file=full_pytm_output,
                llm_json_file=llm_output,
            )

            # Report 3: LLM Explainer Standalone Report
            llm_reporter = LLMExplainerReporter(llm_explainer_html, repo_url)
            llm_reporter.generate(json_file=llm_output)
        else:
            logger.info("--- Stage 6: skipped ---")

        # ---------------------------------------------------------
        # Stage 7: OVERVIEW: Build overview + file viewers for this run
        # ---------------------------------------------------------
        if run_stage[7]:
            logger.info("--- Stage 7: Pipeline Overview Generation ---")
            gh_pages_cfg = pipeline_cfg.get("github_pages", {})
            overview_result = PipelineOverviewGenerator(
                repo_root=BASE_DIR,
                viewer_max_lines=int(gh_pages_cfg.get("viewer_max_lines", 1000)),
                viewer_max_line_chars=int(
                    gh_pages_cfg.get("viewer_max_line_chars", 4000)
                ),
            ).generate(output_dir=output_dir)
        else:
            logger.info("--- Stage 7: skipped ---")
            if run_stage[8]:
                _ensure_artifacts(
                    [pipeline_overview_html],
                    "Stage 8+",
                )

        # ---------------------------------------------------------
        # Stage 8: PUBLISH: Prepare GitHub Pages site in repo docs/
        # ---------------------------------------------------------
        if run_stage[8]:
            logger.info("--- Stage 8: GitHub Pages Publish Prep ---")
            gh_pages_cfg = pipeline_cfg.get("github_pages", {})
            gh_pages_result = GitHubPagesPublisher(
                repo_root=BASE_DIR,
                config=gh_pages_cfg,
            ).publish(output_dir=output_dir)
        else:
            logger.info("--- Stage 8: skipped ---")

        # ---------------------------------------------------------
        # Stage 9: ARCHIVE: Snapshot outputs into timestamped folder
        # ---------------------------------------------------------
        archive_dir = None
        if run_stage[9]:
            logger.info("--- Stage 9: Archiving Outputs ---")
            archive_dir = _archive_outputs(
                output_dir=output_dir,
                files=[
                    jsonl_output,
                    checkov_output,
                    threat_output,
                    full_pytm_output,
                    comparison_output,
                    llm_output,
                    extraction_html,
                    comparison_html,
                    llm_explainer_html,
                    pipeline_overview_html,
                    settings_output,
                    *[
                        path
                        for name, path in log_files.items()
                        if name != "log_dir"
                    ],
                ],
                run_timestamp=run_timestamp,
            )
        else:
            logger.info("--- Stage 9: skipped ---")

        # ---------------------------------------------------------
        # Final Summary
        # ---------------------------------------------------------
        if not comparison_results and Path(comparison_output).exists():
            comparison_results = _load_json(comparison_output, [])

        if not full_pytm_results and Path(full_pytm_output).exists():
            full_pytm_results = _load_json(full_pytm_output, {})

        if not llm_result and Path(llm_output).exists():
            llm_result = _load_json(llm_output, {})

        def _read_field(item: Any, field: str, default: Any = None) -> Any:
            if isinstance(item, dict):
                return item.get(field, default)
            return getattr(item, field, default)

        regressions = sum(
            1 for r in comparison_results
            if _read_field(r, "posture_direction") == "regression"
        )
        improvements = sum(
            1 for r in comparison_results
            if _read_field(r, "posture_direction") == "improvement"
        )
        csi_count = sum(
            1 for r in comparison_results if bool(_read_field(r, "is_csi", False))
        )
        macro_only = sum(
            1 for r in comparison_results if bool(_read_field(r, "macro_only", False))
        )

        logger.info("Pipeline completed successfully.")
        logger.info(f"Regressions: {regressions}, Improvements: {improvements}")
        logger.info(f"CSI Commits: {csi_count}, Macro-only findings: {macro_only}")
        logger.info(
            "Full native PyTM findings: %s",
            full_pytm_results.get("finding_count", 0),
        )
        logger.info(
            "LLM explainer status: %s, items: %s",
            llm_result.get("status", "unknown"),
            len(llm_result.get("items", [])),
        )
        logger.info(
            "Overview generation status: %s, viewer_pages: %s",
            overview_result.get("status", "unknown"),
            overview_result.get("viewer_pages_generated", 0),
        )
        logger.info(
            "GitHub Pages publish status: %s (site_dir=%s)",
            gh_pages_result.get("status", "unknown"),
            gh_pages_result.get("site_dir", ""),
        )
        logger.info("LLM explainer report saved to: %s", llm_explainer_html)
        logger.info("Run logs saved to: %s", log_files["log_dir"])
        logger.info(f"Reports saved to: {output_dir}")
        if archive_dir is not None:
            logger.info(f"Run archive saved to: {archive_dir}")
        logger.info(
            "Executed stage range: %s..%s (%s -> %s)",
            start_stage,
            end_stage,
            STAGE_NAMES.get(start_stage, "unknown"),
            STAGE_NAMES.get(end_stage, "unknown"),
        )

    except Exception as e:
        logger.exception("Pipeline failed with error:")
        raise


if __name__ == "__main__":
    main()
