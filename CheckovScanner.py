"""CheckovScanner.py -- Self-contained Checkov scanner for the PipelineRunner.py pipeline.

Runs Checkov on before/after YAML from extraction results and outputs JSON.
All configuration is read from external YAML files -- nothing is hardcoded:

    config/attack_classes.yaml   -- AC1-AC11 taxonomy with Checkov rule mappings
    config/rule_severity.yaml    -- Checkov rule ID -> severity (CRITICAL/HIGH/MEDIUM/LOW)
    config/stride_categories.yaml -- STRIDE threat model categories

No SQLite.  No imports from the ``monitor`` package.

Classes
-------
CheckovScanner
    Runs Checkov on before/after YAML from extraction results.
CheckovFinding
    A single Checkov finding with severity and attack class enrichment.
CheckovDeltaResult
    Checkov scan results for one extraction delta.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default config directory (relative to this file)
# ---------------------------------------------------------------------------
_DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent / "config"


# ---------------------------------------------------------------------------
# YAML loaders
# ---------------------------------------------------------------------------
def _load_yaml(path: Path) -> dict:
    """Load a YAML file and return its contents as a dict."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# Data class for a single finding
# ---------------------------------------------------------------------------
@dataclass
class CheckovFinding:
    rule_id: str
    title: str
    severity: str
    line_start: int = 0
    attack_classes: list[str] = field(default_factory=list)

    def primary_attack_class(self) -> str:
        """Return the first (highest-priority) attack class, or empty string."""
        return self.attack_classes[0] if self.attack_classes else ""


# ---------------------------------------------------------------------------
# Data class for per-delta Checkov results
# ---------------------------------------------------------------------------
@dataclass
class CheckovDeltaResult:
    """Checkov scan results for one extraction delta (one file in one commit)."""

    commit_sha: str
    file_path: str
    before_findings: List[Dict[str, Any]]
    after_findings: List[Dict[str, Any]]
    before_count: int = 0
    after_count: int = 0
    delta: int = 0  # after_count - before_count


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------
class CheckovScanner:
    """Run Checkov on before/after YAML from extraction results.

    All configuration is loaded from YAML files at construction time.
    The class is fully self-contained -- no ``monitor`` package imports.

    Parameters
    ----------
    config : dict
        Parsed ``pipeline_config.yaml`` contents (or equivalent dict built
        by PipelineRunner.py).  Only the ``checkov`` section is used.
    attack_classes_cfg : dict | None
        Parsed ``attack_classes.yaml``.  If *None*, the file is loaded from
        ``config/attack_classes.yaml`` relative to this script.
    rule_severity_cfg : dict | None
        Parsed ``rule_severity.yaml``.  If *None*, the file is loaded from
        ``config/rule_severity.yaml`` relative to this script.
    stride_cfg : dict | None
        Parsed ``stride_categories.yaml``.  If *None*, the file is loaded
        from ``config/stride_categories.yaml`` relative to this script.
    config_dir : str | Path | None
        Base directory for YAML config files.  Defaults to ``config/``
        next to this script.
    """

    def __init__(
        self,
        config: dict,
        attack_classes_cfg: Optional[dict] = None,
        rule_severity_cfg: Optional[dict] = None,
        stride_cfg: Optional[dict] = None,
        config_dir: Optional[str | Path] = None,
    ) -> None:
        # Resolve config directory
        cfg_dir = Path(config_dir) if config_dir else _DEFAULT_CONFIG_DIR

        # --- Checkov runtime settings from pipeline config ----------------
        checkov_cfg = config.get("checkov", {})
        self.timeout: int = checkov_cfg.get("timeout", 60)
        self.skip_non_yaml: bool = checkov_cfg.get("skip_non_yaml", True)
        self.workers: int = checkov_cfg.get("workers", 4)
        self.framework: str = checkov_cfg.get("framework", "kubernetes")

        # --- Attack classes (AC1-AC11) ------------------------------------
        if attack_classes_cfg is None:
            attack_classes_cfg = _load_yaml(cfg_dir / "attack_classes.yaml")
        self._attack_classes_cfg = attack_classes_cfg

        # Build rule -> AC mapping from attack class definitions
        self._rule_to_ac: Dict[str, List[str]] = {}
        for ac in attack_classes_cfg.get("attack_classes", []):
            for rule in ac.get("checkov_rules", []):
                self._rule_to_ac.setdefault(rule, []).append(ac["id"])

        # --- Rule severity ------------------------------------------------
        if rule_severity_cfg is None:
            rule_severity_cfg = _load_yaml(cfg_dir / "rule_severity.yaml")
        self._severity_map: Dict[str, str] = rule_severity_cfg

        # --- STRIDE categories --------------------------------------------
        if stride_cfg is None:
            stride_cfg = _load_yaml(cfg_dir / "stride_categories.yaml")
        self._stride_cfg = stride_cfg

        # Build STRIDE category -> list of attack class IDs for enrichment
        self._stride_to_ac: Dict[str, List[str]] = stride_cfg.get(
            "stride_to_attack_classes", {}
        )

        logger.info(
            "CheckovScanner initialised: %d attack classes, %d severity rules, "
            "%d STRIDE categories",
            len(attack_classes_cfg.get("attack_classes", [])),
            len(self._severity_map),
            len(self._stride_to_ac),
        )

    # -----------------------------------------------------------------
    # Input: load extraction deltas from JSONL file
    # -----------------------------------------------------------------
    @staticmethod
    def load_deltas(jsonl_path: str | Path) -> List[Dict[str, Any]]:
        """Load extraction deltas from a JSONL file (one JSON object per line).

        This is the output of ``SecurityDeltaExtractor`` (``security_results.jsonl``).
        Each line is a JSON object with keys: ``commit_sha``, ``file``,
        ``before``, ``after``, ``diff``, ``keywords_matched``, etc.

        Parameters
        ----------
        jsonl_path : str | Path
            Path to the ``.jsonl`` file produced by the extraction stage.

        Returns
        -------
        list[dict]
            Parsed delta dicts ready for ``scan_deltas()``.

        Raises
        ------
        FileNotFoundError
            If *jsonl_path* does not exist.
        """
        path = Path(jsonl_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Extraction results not found: {path}\n"
                f"Run SecurityDeltaExtractor first to produce this file."
            )

        deltas: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    deltas.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning(
                        "Skipping invalid JSON at %s:%d", path, lineno
                    )

        logger.info("Loaded %d deltas from %s", len(deltas), path)
        return deltas

    def scan_deltas_from_file(
        self, jsonl_path: str | Path
    ) -> List[CheckovDeltaResult]:
        """Load deltas from a JSONL file and scan them.

        Convenience method that combines ``load_deltas()`` and
        ``scan_deltas()`` into a single call, making the file-based
        data contract explicit.

        Parameters
        ----------
        jsonl_path : str | Path
            Path to ``security_results.jsonl``.

        Returns
        -------
        list[CheckovDeltaResult]
            Scan results (same as ``scan_deltas()``).
        """
        deltas = self.load_deltas(jsonl_path)
        return self.scan_deltas(deltas)

    # -----------------------------------------------------------------
    # Severity lookup (instance method using YAML config)
    # -----------------------------------------------------------------
    def map_severity(self, rule_id: str) -> str:
        """Map a Checkov rule ID to a severity string using rule_severity.yaml."""
        return self._severity_map.get(rule_id, "MEDIUM")

    # -----------------------------------------------------------------
    # Attack class lookup (instance method using YAML config)
    # -----------------------------------------------------------------
    def rule_to_attack_classes(self, rule_id: str) -> List[str]:
        """Return attack class IDs that a Checkov rule maps to."""
        return self._rule_to_ac.get(rule_id, [])

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    def scan_deltas(
        self, deltas: List[Dict[str, Any]]
    ) -> List[CheckovDeltaResult]:
        """Scan all extraction deltas, return per-delta Checkov results.

        Uses ThreadPoolExecutor for parallel scanning.  The number of
        workers is controlled by the ``checkov.workers`` setting
        (default 4).  Each worker runs Checkov as a subprocess, so
        threads are ideal (I/O-bound, not CPU-bound).

        Parameters
        ----------
        deltas : list[dict]
            Output from ``SecurityDeltaExtractor.run()``.  Each dict has
            ``commit_sha``, ``file``, ``before``, ``after`` keys.

        Returns
        -------
        list[CheckovDeltaResult]
            One result per delta that was scannable, in the same order
            as the input ``deltas`` list.
        """
        total = len(deltas)
        workers = max(1, self.workers)
        logger.info(
            "Checkov scanning %d deltas with %d parallel workers",
            total, workers,
        )

        if workers == 1:
            return self._scan_deltas_sequential(deltas)

        # Submit all deltas to the thread pool
        results: List[Optional[CheckovDeltaResult]] = [None] * total

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_idx = {
                pool.submit(self._scan_one_delta, delta, idx, total): idx
                for idx, delta in enumerate(deltas)
            }

            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception:
                    sha = deltas[idx].get("commit_sha", "?")
                    fpath = deltas[idx].get("file", "?")
                    logger.exception(
                        "Checkov worker failed for %s @ %s", fpath, sha[:8],
                    )
                    results[idx] = CheckovDeltaResult(
                        commit_sha=sha,
                        file_path=fpath,
                        before_findings=[],
                        after_findings=[],
                    )

        return [r for r in results if r is not None]

    # -----------------------------------------------------------------
    # Internal: scan a single delta (used by both parallel & sequential)
    # -----------------------------------------------------------------
    def _scan_one_delta(
        self, delta: Dict[str, Any], idx: int, total: int,
    ) -> CheckovDeltaResult:
        """Scan one delta's BEFORE/AFTER content and return the result."""
        sha = delta.get("commit_sha", "")
        fpath = delta.get("file", "")

        logger.info(
            "[%d/%d] Checkov scanning %s @ %s",
            idx + 1, total, fpath, sha[:8],
        )

        before_findings = self._scan_content(
            delta.get("before", ""), f"BEFORE:{fpath}"
        )
        after_findings = self._scan_content(
            delta.get("after", ""), f"AFTER:{fpath}"
        )

        return CheckovDeltaResult(
            commit_sha=sha,
            file_path=fpath,
            before_findings=[
                self._finding_to_dict(f) for f in before_findings
            ],
            after_findings=[
                self._finding_to_dict(f) for f in after_findings
            ],
            before_count=len(before_findings),
            after_count=len(after_findings),
            delta=len(after_findings) - len(before_findings),
        )

    def _scan_deltas_sequential(
        self, deltas: List[Dict[str, Any]]
    ) -> List[CheckovDeltaResult]:
        """Sequential fallback when workers == 1."""
        total = len(deltas)
        return [
            self._scan_one_delta(delta, idx, total)
            for idx, delta in enumerate(deltas)
        ]

    @staticmethod
    def save_json(
        results: List[CheckovDeltaResult], output_path: str
    ) -> None:
        """Save results to a JSON file."""
        data = [
            {
                "commit_sha": r.commit_sha,
                "file_path": r.file_path,
                "before_findings": r.before_findings,
                "after_findings": r.after_findings,
                "before_count": r.before_count,
                "after_count": r.after_count,
                "delta": r.delta,
            }
            for r in results
        ]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("Saved %d Checkov results to %s", len(data), output_path)

    # ---------------------------------------------------------------------------
    # Core: run Checkov on a YAML string (self-contained, no external imports)
    # ---------------------------------------------------------------------------
    def run_checkov(
        self,
        yaml_content: str,
        filename: str = "manifest.yaml",
        timeout: int | None = None,
    ) -> list[CheckovFinding]:
        """Run Checkov on a single YAML string, return list of findings.

        If Checkov is not installed or crashes, returns an empty list and logs
        a warning (graceful degradation).

        Severity and attack-class enrichment uses the YAML configs loaded
        at construction time (rule_severity.yaml, attack_classes.yaml).
        """
        if timeout is None:
            timeout = self.timeout

        if not yaml_content or not yaml_content.strip():
            return []

        with tempfile.NamedTemporaryFile(
                suffix=".yaml", mode="w", delete=False, prefix="iac_mon_"
        ) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            result = subprocess.run(
                [
                    "checkov",
                    "-f", tmp_path,
                    "--framework", self.framework,
                    "--output", "json",
                    "--compact",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode not in (0, 1):
                err = (result.stderr or "").strip().replace("\n", " ")
                logger.warning(
                    "Checkov exited with code %d on %s%s",
                    result.returncode,
                    filename,
                    f" (stderr: {err[:300]})" if err else "",
                )
        except FileNotFoundError:
            logger.warning("Checkov not found on PATH -- install with: pip install checkov")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("Checkov timed out on %s", filename)
            return []
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        findings: list[CheckovFinding] = []

        if not result.stdout or not result.stdout.strip():
            return findings

        raw = result.stdout.strip()

        # Checkov may print log lines or warnings before the JSON payload.
        # Find the first '{' or '[' that starts the actual JSON.
        json_start = -1
        for i, ch in enumerate(raw):
            if ch in ('{', '['):
                json_start = i
                break

        if json_start < 0:
            logger.warning(
                "No JSON found in Checkov output for %s (len=%d)",
                filename, len(raw),
            )
            return findings

        if json_start > 0:
            logger.debug(
                "Stripped %d leading non-JSON chars from Checkov output for %s",
                json_start, filename,
            )

        raw = raw[json_start:]

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            try:
                decoder = json.JSONDecoder()
                data, _ = decoder.raw_decode(raw)
            except (json.JSONDecodeError, ValueError):
                logger.warning(
                    "Could not parse Checkov JSON output for %s "
                    "(first 200 chars: %.200s)",
                    filename, raw,
                )
                return findings

        # Handle both single-result dict and list-of-dicts
        if isinstance(data, list):
            results_list = data
        else:
            results_list = [data]

        for result_block in results_list:
            if not isinstance(result_block, dict):
                continue

            failed_checks = result_block.get("results", {}).get("failed_checks", [])
            for check in failed_checks:
                rule_id = check.get("check_id", "")
                title = (
                    check.get("check_name", "")
                    or check.get("check_result", {}).get("name", "")
                    or check.get("name", "")
                )
                line_range = check.get("file_line_range", [0, 0])
                line = (
                    line_range[0]
                    if isinstance(line_range, list) and line_range
                    else 0
                )

                # Enrich from YAML configs (not hardcoded)
                ac_ids = self.rule_to_attack_classes(rule_id)
                severity = self.map_severity(rule_id)

                findings.append(CheckovFinding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    line_start=line,
                    attack_classes=ac_ids,
                ))

        return findings

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------
    def _scan_content(
        self, content: Optional[str], label: str
    ) -> List[CheckovFinding]:
        """Run Checkov on a single YAML string and return enriched findings."""
        if not content or not content.strip():
            return []

        if self.skip_non_yaml:
            if "apiVersion:" not in content and "kind:" not in content:
                return []

        findings = self.run_checkov(content, filename=label)

        # Additional enrichment pass: overlay AC mapping and severity
        # from YAML configs (handles any rules that run_checkov may
        # have assigned defaults to)
        for f in findings:
            if not f.attack_classes:
                f.attack_classes = self._rule_to_ac.get(f.rule_id, [])
            yaml_severity = self._severity_map.get(f.rule_id)
            if yaml_severity:
                f.severity = yaml_severity

        return findings

    @staticmethod
    def _finding_to_dict(finding: CheckovFinding) -> Dict[str, Any]:
        """Serialise a CheckovFinding to a plain dict for JSON output."""
        return {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "line_start": finding.line_start,
            "attack_classes": finding.attack_classes,
        }

    # -----------------------------------------------------------------
    # Accessors for loaded configuration (useful for reporting / debug)
    # -----------------------------------------------------------------
    @property
    def attack_classes_config(self) -> dict:
        """Return the loaded attack_classes.yaml contents."""
        return self._attack_classes_cfg

    @property
    def stride_config(self) -> dict:
        """Return the loaded stride_categories.yaml contents."""
        return self._stride_cfg

    @property
    def severity_map(self) -> Dict[str, str]:
        """Return the loaded rule_severity.yaml contents."""
        return dict(self._severity_map)
