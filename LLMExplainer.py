#!/usr/bin/env python3
"""LLMExplainer.py -- Explain top security findings with an OpenRouter LLM.

This component reads pipeline outputs, selects top-risk deltas, sends a
grounded prompt to OpenRouter, and writes a machine-readable explanation JSON.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set


logger = logging.getLogger(__name__)

_DEFAULT_PROMPT = """You are a Senior DevSecOps Architect and Security Analyst.
Explain only what is supported by the provided structured findings.
Return strict JSON only with:
{
  "overall_posture": "regression|improvement|mixed|no_material_change",
  "executive_summary": "string",
  "items": [
    {
      "title": "string",
      "posture_direction": "regression|improvement|neutral",
      "severity": "critical|high|medium|low|info|unknown",
      "attack_class": "string",
      "vulnerability_summary": "string",
      "security_impact": "string",
      "recommended_action": "string",
      "confidence": 0.0
    }
  ],
  "limitations": ["string"]
}
"""


class LLMExplainer:
    """Generate LLM-based explanations for top comparison findings."""

    def __init__(
        self,
        config: Dict[str, Any],
        prompt_template_path: Optional[str | Path] = None,
    ) -> None:
        cfg = config.get("llm_explainer", {})
        self.enabled: bool = bool(cfg.get("enabled", True))
        self.top_n: int = int(cfg.get("top_n", 5))
        self.timeout_seconds: int = int(cfg.get("timeout_seconds", 90))
        self.max_output_tokens: int = int(cfg.get("max_output_tokens", 1800))
        self.temperature: float = float(cfg.get("temperature", 0.2))
        self.model: str = (
            os.environ.get("OPENROUTER_MODEL")
            or cfg.get("model", "deepseek/deepseek-chat-v3-0324:free")
        )
        self.base_url: str = cfg.get("base_url", "https://openrouter.ai/api/v1")
        self.http_referer: str = cfg.get("http_referer", "http://localhost:5000")
        self.app_title: str = cfg.get("app_title", "SecurityExtractorPipeline")

        template_path = Path(prompt_template_path) if prompt_template_path else None
        self.prompt_template = self._load_prompt_template(template_path)

    def explain_from_files(
        self,
        comparison_json_file: str | Path,
        extraction_jsonl_file: str | Path,
        full_pytm_json_file: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """Run LLM explanation generation from pipeline output files."""
        start = datetime.now().isoformat()
        comparison_path = Path(comparison_json_file)
        extraction_path = Path(extraction_jsonl_file)
        full_pytm_path = Path(full_pytm_json_file) if full_pytm_json_file else None

        if not self.enabled:
            return self._skipped_result(
                reason="llm_explainer.enabled is false",
                generated_at=start,
            )

        api_key = self._get_api_key()
        if not api_key:
            return self._skipped_result(
                reason="OPENROUTER_API_KEY not found in environment or .env",
                generated_at=start,
            )

        if not comparison_path.exists():
            return self._error_result(
                error=f"Comparison file not found: {comparison_path}",
                generated_at=start,
            )
        if not extraction_path.exists():
            return self._error_result(
                error=f"Extraction JSONL not found: {extraction_path}",
                generated_at=start,
            )

        comparison_results = self._load_json(comparison_path)
        if not isinstance(comparison_results, list):
            return self._error_result(
                error="comparison_results.json must contain a list",
                generated_at=start,
            )

        top_items = self._select_top_items(comparison_results)
        if not top_items:
            return {
                "status": "ok",
                "generated_at": start,
                "provider": "openrouter",
                "model": self.model,
                "top_n_requested": self.top_n,
                "top_n_used": 0,
                "overall_posture": "no_material_change",
                "executive_summary": "No findings available for LLM explanation.",
                "items": [],
                "limitations": ["No top findings selected from comparison results."],
                "llm_raw_response": "",
                "llm_parsed_response": {},
                "input_files": {
                    "comparison_json": str(comparison_path),
                    "extraction_jsonl": str(extraction_path),
                    "full_pytm_json": str(full_pytm_path) if full_pytm_path else "",
                },
            }

        keys = {self._delta_key(i) for i in top_items}
        extraction_context = self._load_extraction_context(extraction_path, keys)
        full_pytm_summary = self._load_full_pytm_summary(full_pytm_path)

        prompt_payload = {
            "analysis_scope": {
                "top_n_requested": self.top_n,
                "top_n_selected": len(top_items),
            },
            "full_pytm_summary": full_pytm_summary,
            "top_findings": [
                self._build_finding_context(item, extraction_context)
                for item in top_items
            ],
        }

        user_prompt = (
            f"{self.prompt_template}\n\n"
            "PIPELINE INPUT JSON (ground truth):\n"
            f"{json.dumps(prompt_payload, ensure_ascii=False, indent=2)}\n\n"
            "Output JSON only."
        )
        messages = [
            {"role": "system", "content": "You are a strict JSON security explainer."},
            {"role": "user", "content": user_prompt},
        ]

        llm_raw = ""
        llm_parsed: Dict[str, Any] = {}
        try:
            llm_raw = self._call_openrouter(messages=messages, api_key=api_key)
            llm_parsed = self._parse_json_response(llm_raw)
        except Exception as exc:
            logger.exception("LLM explanation call failed.")
            return self._error_result(
                error=str(exc),
                generated_at=start,
                top_items=top_items,
            )

        normalized_items = self._normalize_items(top_items, llm_parsed.get("items", []))
        return {
            "status": "ok",
            "generated_at": start,
            "provider": "openrouter",
            "model": self.model,
            "top_n_requested": self.top_n,
            "top_n_used": len(top_items),
            "overall_posture": llm_parsed.get("overall_posture", "unknown"),
            "executive_summary": llm_parsed.get("executive_summary", ""),
            "items": normalized_items,
            "limitations": llm_parsed.get("limitations", []),
            "llm_raw_response": llm_raw,
            "llm_parsed_response": llm_parsed,
            "input_files": {
                "comparison_json": str(comparison_path),
                "extraction_jsonl": str(extraction_path),
                "full_pytm_json": str(full_pytm_path) if full_pytm_path else "",
            },
        }

    @staticmethod
    def save_json(result: Dict[str, Any], output_path: str | Path) -> None:
        """Persist LLM explanation JSON to disk."""
        out_path = Path(output_path)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        logger.info("Saved LLM explanations to %s", out_path)

    @staticmethod
    def _load_prompt_template(path: Optional[Path]) -> str:
        if path and path.exists():
            return path.read_text(encoding="utf-8", errors="replace").strip()
        return _DEFAULT_PROMPT

    @staticmethod
    def _load_json(path: Path) -> Any:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _delta_key(item: Dict[str, Any]) -> str:
        return f"{item.get('commit_sha', '')}:{item.get('file_path', '')}"

    def _select_top_items(self, comparison_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        scored = sorted(
            comparison_results,
            key=lambda r: (
                1 if r.get("is_csi") else 0,
                float(r.get("composite_score", 0.0)),
                abs(int(r.get("checkov_delta", 0))) + abs(int(r.get("threat_risk_delta", 0))),
                int(r.get("threat_finding_count", 0)),
            ),
            reverse=True,
        )
        material = [
            r for r in scored
            if r.get("is_csi")
            or int(r.get("checkov_delta", 0)) != 0
            or int(r.get("threat_finding_count", 0)) > 0
        ]
        base = material if material else scored
        return base[: max(1, self.top_n)]

    @staticmethod
    def _load_extraction_context(path: Path, keys: Set[str]) -> Dict[str, Dict[str, Any]]:
        found: Dict[str, Dict[str, Any]] = {}
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = f"{obj.get('commit_sha', '')}:{obj.get('file', '')}"
                if key not in keys:
                    continue
                found[key] = {
                    "diff": LLMExplainer._truncate_text(obj.get("diff", ""), 1600),
                    "keywords_matched": obj.get("keywords_matched", []),
                }
                if len(found) >= len(keys):
                    break
        return found

    @staticmethod
    def _load_full_pytm_summary(path: Optional[Path]) -> Dict[str, Any]:
        if not path or not path.exists():
            return {}
        try:
            data = LLMExplainer._load_json(path)
            return {
                "finding_count": data.get("finding_count", 0),
                "severity_counts": data.get("severity_counts", {}),
                "element_count": data.get("element_count", 0),
                "flow_count": data.get("flow_count", 0),
            }
        except Exception:
            return {}

    @staticmethod
    def _truncate_text(value: str, max_chars: int) -> str:
        if not value:
            return ""
        if len(value) <= max_chars:
            return value
        return value[:max_chars] + "\n...[truncated]"

    def _build_finding_context(
        self,
        comparison_item: Dict[str, Any],
        extraction_context: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        key = self._delta_key(comparison_item)
        ext = extraction_context.get(key, {})
        checkov_findings = []
        for f in comparison_item.get("checkov_findings_after", [])[:3]:
            checkov_findings.append(
                {
                    "rule_id": f.get("rule_id", ""),
                    "severity": f.get("severity", ""),
                    "title": f.get("title", ""),
                    "resource": f.get("resource", ""),
                }
            )
        threat_findings = []
        for f in comparison_item.get("threat_findings", [])[:3]:
            threat_findings.append(
                {
                    "change_type": f.get("change_type", ""),
                    "element_name": f.get("element_name", ""),
                    "severity": f.get("severity", ""),
                    "attack_class": f.get("attack_class", ""),
                }
            )
        return {
            "rank_metadata": {
                "composite_score": comparison_item.get("composite_score", 0.0),
                "is_csi": bool(comparison_item.get("is_csi", False)),
                "posture_direction": comparison_item.get("posture_direction", "neutral"),
            },
            "commit_sha": comparison_item.get("commit_sha", ""),
            "file_path": comparison_item.get("file_path", ""),
            "commit_message": comparison_item.get("commit_message", ""),
            "attack_class": comparison_item.get("attack_class", ""),
            "checkov_delta": comparison_item.get("checkov_delta", 0),
            "threat_risk_delta": comparison_item.get("threat_risk_delta", 0),
            "labels_before": comparison_item.get("labels_before", []),
            "labels_after": comparison_item.get("labels_after", []),
            "checkov_findings_top": checkov_findings,
            "threat_findings_top": threat_findings,
            "extraction_keywords": ext.get("keywords_matched", []),
            "diff_excerpt": ext.get("diff", ""),
        }

    def _call_openrouter(self, messages: List[Dict[str, str]], api_key: str) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url=f"{self.base_url.rstrip('/')}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": self.http_referer,
                "X-Title": self.app_title,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenRouter HTTP error {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenRouter connection error: {exc}") from exc

        parsed = json.loads(raw)
        choices = parsed.get("choices", [])
        if not choices:
            raise RuntimeError("OpenRouter response contained no choices.")
        msg = choices[0].get("message", {})
        content = msg.get("content", "")
        if not content:
            raise RuntimeError("OpenRouter response had empty message content.")
        return content

    @staticmethod
    def _parse_json_response(response_text: str) -> Dict[str, Any]:
        text = response_text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            lines = text.splitlines()
            if lines and lines[0].strip().lower() == "json":
                lines = lines[1:]
            text = "\n".join(lines).strip()

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = text[start : end + 1]
            try:
                parsed = json.loads(snippet)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        return {}

    @staticmethod
    def _normalize_items(
        top_items: List[Dict[str, Any]],
        llm_items: Iterable[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        llm_items_list = list(llm_items)
        normalized: List[Dict[str, Any]] = []
        for idx, base in enumerate(top_items, start=1):
            raw_llm = llm_items_list[idx - 1] if idx - 1 < len(llm_items_list) else {}
            llm = raw_llm if isinstance(raw_llm, dict) else {}
            remediation = (
                llm.get("remediation", {})
                if isinstance(llm.get("remediation"), dict)
                else {}
            )
            macro_view = llm.get("macro_view", {})
            macro_impact = macro_view.get("impact", "") if isinstance(macro_view, dict) else ""
            normalized.append(
                {
                    "rank": idx,
                    "commit_sha": base.get("commit_sha", ""),
                    "file_path": base.get("file_path", ""),
                    "composite_score": base.get("composite_score", 0.0),
                    "posture_direction": llm.get(
                        "posture_direction",
                        base.get("posture_direction", "neutral"),
                    ),
                    "severity": llm.get("severity", "unknown"),
                    "attack_class": llm.get("attack_class", base.get("attack_class", "")),
                    "title": llm.get("title", ""),
                    "vulnerability_summary": llm.get("vulnerability_summary", ""),
                    "security_impact": llm.get("security_impact", macro_impact),
                    "recommended_action": llm.get(
                        "recommended_action",
                        remediation.get("developer_action", ""),
                    ),
                    "confidence": llm.get("confidence", 0.0),
                }
            )
        return normalized

    @staticmethod
    def _parse_dotenv_line(line: str) -> Optional[tuple[str, str]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            return None
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            return None
        return key, value

    @staticmethod
    def _load_dotenv(path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = LLMExplainer._parse_dotenv_line(line)
            if not parsed:
                continue
            key, value = parsed
            if key not in os.environ:
                os.environ[key] = value

    def _get_api_key(self) -> str:
        if os.environ.get("OPENROUTER_API_KEY"):
            return os.environ["OPENROUTER_API_KEY"]
        cwd_env = Path.cwd() / ".env"
        self._load_dotenv(cwd_env)
        if os.environ.get("OPENROUTER_API_KEY"):
            return os.environ["OPENROUTER_API_KEY"]
        local_env = Path(__file__).resolve().parent / ".env"
        self._load_dotenv(local_env)
        return os.environ.get("OPENROUTER_API_KEY", "")

    def _skipped_result(self, reason: str, generated_at: str) -> Dict[str, Any]:
        logger.warning("Skipping LLM explanations: %s", reason)
        return {
            "status": "skipped",
            "generated_at": generated_at,
            "provider": "openrouter",
            "model": self.model,
            "top_n_requested": self.top_n,
            "top_n_used": 0,
            "overall_posture": "unknown",
            "executive_summary": "",
            "items": [],
            "limitations": [reason],
            "llm_raw_response": "",
            "llm_parsed_response": {},
        }

    def _error_result(
        self,
        error: str,
        generated_at: str,
        top_items: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        logger.error("LLM explanation error: %s", error)
        return {
            "status": "error",
            "generated_at": generated_at,
            "provider": "openrouter",
            "model": self.model,
            "top_n_requested": self.top_n,
            "top_n_used": len(top_items) if top_items else 0,
            "overall_posture": "unknown",
            "executive_summary": "",
            "items": self._normalize_items(top_items or [], []),
            "limitations": [error],
            "llm_raw_response": "",
            "llm_parsed_response": {},
        }


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run OpenRouter LLM explanations for top findings.")
    parser.add_argument("--comparison-json", required=True, help="Path to comparison_results.json")
    parser.add_argument("--extraction-jsonl", required=True, help="Path to security_results.jsonl")
    parser.add_argument("--full-pytm-json", default="", help="Path to full_pytm_results.json")
    parser.add_argument("--output-json", required=True, help="Path to write llm_explanations.json")
    parser.add_argument(
        "--prompt-template",
        default="docu/llm_prompt_example.txt",
        help="Path to LLM prompt template text",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=5,
        help="Number of top findings to explain",
    )
    return parser


def main() -> None:
    parser = _build_cli_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    cfg: Dict[str, Any] = {
        "llm_explainer": {
            "enabled": True,
            "top_n": args.top_n,
        }
    }
    explainer = LLMExplainer(cfg, prompt_template_path=args.prompt_template)
    result = explainer.explain_from_files(
        comparison_json_file=args.comparison_json,
        extraction_jsonl_file=args.extraction_jsonl,
        full_pytm_json_file=args.full_pytm_json or None,
    )
    explainer.save_json(result, args.output_json)


if __name__ == "__main__":
    main()
