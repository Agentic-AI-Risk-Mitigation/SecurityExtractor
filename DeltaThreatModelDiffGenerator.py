"""DeltaThreatModelDiffGenerator.py -- Delta-focused threat model generator for the pipeline.

Builds lightweight PyTM-style threat models from before/after Kubernetes YAML,
computes security diffs, and outputs JSON.  All configuration is read from
external YAML files -- nothing is hardcoded:

    config/k8s_kind_map.yaml       -- K8S kind -> PyTM element kind mapping
    config/threat_model_config.yaml -- Label flips, risky combos, hardening labels

No SQLite.  No imports from the ``monitor`` package.

Classes
-------
DeltaThreatModelDiffGenerator
    Builds threat models from before/after YAML and computes diffs.
K8sElement
    A single K8S resource mapped to a PyTM-style element.
K8sModel
    A complete threat model built from one state of K8S YAML.
ThreatFinding
    A single threat finding from before/after comparison.
ThreatModelDeltaResult
    Threat model diff results for one extraction delta.
"""

from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default config directory (relative to this file)
# ---------------------------------------------------------------------------
_DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent / "config"


def _load_yaml(path: Path) -> dict:
    """Load a YAML file and return its contents as a dict."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ===================================================================
# Data classes
# ===================================================================

# ---------------------------------------------------------------------------
# K8S element and model (from pytm_mapper.py)
# ---------------------------------------------------------------------------
@dataclass
class K8sElement:
    """A K8S resource mapped to a PyTM-style element."""

    kind: str               # PyTM kind: Process, Dataflow, Datastore, etc.
    name: str               # metadata.name
    namespace: str           # metadata.namespace (default: "default")
    labels: set[str]         # security labels from label inference
    source_resource: str     # original K8S kind (e.g. "Deployment")
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class K8sModel:
    """A complete threat model built from one state of K8S YAML."""

    elements: list[K8sElement] = field(default_factory=list)

    def get_by_kind(self, kind: str) -> list[K8sElement]:
        """Return elements matching the given PyTM kind."""
        return [e for e in self.elements if e.kind == kind]

    @property
    def all_labels(self) -> set[str]:
        """Union of all security labels across all elements."""
        result: set[str] = set()
        for e in self.elements:
            result |= e.labels
        return result

    def processes(self) -> list[K8sElement]:
        """Return all Process elements (workloads)."""
        return self.get_by_kind("Process")

    def boundaries(self) -> list[K8sElement]:
        """Return all Boundary elements (NetworkPolicies, Namespaces)."""
        return self.get_by_kind("Boundary")


# ---------------------------------------------------------------------------
# Threat diff types (from threat_diff.py)
# ---------------------------------------------------------------------------
class ChangeType(str, Enum):
    """Types of security-relevant changes detected between models."""

    LABEL_FLIP = "LABEL_FLIP"
    BOUNDARY_REMOVED = "BOUNDARY_REMOVED"
    BOUNDARY_ADDED = "BOUNDARY_ADDED"
    NEW_RISKY_COMBO = "NEW_RISKY_COMBO"
    NEW_UNHARDENED = "NEW_UNHARDENED"
    ELEMENT_ADDED = "ELEMENT_ADDED"
    ELEMENT_REMOVED = "ELEMENT_REMOVED"
    NONE = "NONE"


@dataclass
class ThreatFinding:
    """A single threat finding from before/after comparison."""

    change_type: ChangeType
    element_name: str
    labels_before: list[str]
    labels_after: list[str]
    attack_class: str
    severity: str


# ---------------------------------------------------------------------------
# Per-delta result
# ---------------------------------------------------------------------------
@dataclass
class ThreatModelDeltaResult:
    """Threat model diff results for one extraction delta."""

    commit_sha: str
    file_path: str
    findings: List[Dict[str, Any]]
    finding_count: int = 0
    risk_delta: int = 0
    before_element_count: int = 0
    after_element_count: int = 0
    before_labels: List[str] = field(default_factory=list)
    after_labels: List[str] = field(default_factory=list)


# ===================================================================
# Main generator class
# ===================================================================
class DeltaThreatModelDiffGenerator:
    """Build threat models from before/after K8S YAML and compute diffs.

    All configuration is loaded from YAML files at construction time.
    The class is fully self-contained -- no ``monitor`` package imports.

    Parameters
    ----------
    config : dict
        Parsed ``pipeline_config.yaml`` (or equivalent dict from PipelineRunner.py).
        Uses the ``threat_model`` and ``comparison.severity_weights`` sections.
    k8s_kind_map_cfg : dict | None
        Parsed ``k8s_kind_map.yaml``.  Auto-loaded from *config_dir* if None.
    threat_model_cfg : dict | None
        Parsed ``threat_model_config.yaml``.  Auto-loaded if None.
    config_dir : str | Path | None
        Base directory for YAML config files.  Defaults to ``config/``
        next to this script.
    """

    def __init__(
        self,
        config: dict,
        k8s_kind_map_cfg: Optional[dict] = None,
        threat_model_cfg: Optional[dict] = None,
        config_dir: Optional[str | Path] = None,
    ) -> None:
        cfg_dir = Path(config_dir) if config_dir else _DEFAULT_CONFIG_DIR

        # --- Runtime settings from pipeline config -----------------------
        tm_cfg = config.get("threat_model", {})
        self.skip_non_k8s: bool = tm_cfg.get("skip_non_k8s", True)

        self._severity_weights: Dict[str, int] = config.get(
            "comparison", {},
        ).get(
            "severity_weights",
            {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0},
        )

        # --- K8S kind map ------------------------------------------------
        if k8s_kind_map_cfg is None:
            k8s_kind_map_cfg = _load_yaml(cfg_dir / "k8s_kind_map.yaml")
        self._k8s_kind_map_cfg = k8s_kind_map_cfg

        self._kind_map: Dict[str, str] = k8s_kind_map_cfg.get("kind_map", {})
        self._workload_kinds: frozenset[str] = frozenset(
            k8s_kind_map_cfg.get("workload_kinds", [])
        )

        # --- Threat model config (label flips, combos, hardening) --------
        if threat_model_cfg is None:
            threat_model_cfg = _load_yaml(
                cfg_dir / "threat_model_config.yaml"
            )
        self._threat_model_cfg = threat_model_cfg

        # Parse label flips into lookup dict: (secure, insecure) -> (AC, severity)
        self._label_flip_ac: Dict[Tuple[str, str], Tuple[str, str]] = {}
        for flip in threat_model_cfg.get("label_flips", []):
            key = (flip["secure"], flip["insecure"])
            self._label_flip_ac[key] = (flip["attack_class"], flip["severity"])

        # Parse risky combos into lookup: frozenset(labels) -> (AC, severity)
        self._risky_combos: Dict[frozenset[str], Tuple[str, str]] = {}
        for combo in threat_model_cfg.get("risky_combos", []):
            key = frozenset(combo["labels"])
            self._risky_combos[key] = (combo["attack_class"], combo["severity"])

        # Hardening labels
        self._hardening_labels: frozenset[str] = frozenset(
            threat_model_cfg.get("hardening_labels", [])
        )

        # Secret detection pattern for ConfigMaps
        pattern_str = threat_model_cfg.get(
            "secret_pattern",
            r"(?i)(password|secret|token|api.?key|credential|private.?key|auth)",
        )
        self._secret_pattern: re.Pattern = re.compile(pattern_str)

        # Read-only RBAC verbs
        self._readonly_verbs: frozenset[str] = frozenset(
            threat_model_cfg.get("readonly_verbs", ["get", "list", "watch"])
        )

        logger.info(
            "DeltaThreatModelDiffGenerator initialised: %d kind mappings, %d label flips, "
            "%d risky combos, %d hardening labels",
            len(self._kind_map),
            len(self._label_flip_ac),
            len(self._risky_combos),
            len(self._hardening_labels),
        )

    # ===================================================================
    # Input: load extraction deltas from JSONL file
    # ===================================================================
    @staticmethod
    def load_deltas(jsonl_path: str | Path) -> List[Dict[str, Any]]:
        """Load extraction deltas from a JSONL file.

        Parameters
        ----------
        jsonl_path : str | Path
            Path to ``security_results.jsonl``.

        Returns
        -------
        list[dict]
            Parsed delta dicts ready for ``model_deltas()``.

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

    def model_deltas_from_file(
        self, jsonl_path: str | Path,
    ) -> List[ThreatModelDeltaResult]:
        """Load deltas from a JSONL file and run threat modelling.

        Convenience method combining ``load_deltas()`` + ``model_deltas()``.

        Parameters
        ----------
        jsonl_path : str | Path
            Path to ``security_results.jsonl``.
        """
        deltas = self.load_deltas(jsonl_path)
        return self.model_deltas(deltas)

    # ===================================================================
    # Public API
    # ===================================================================
    def model_deltas(
        self, deltas: List[Dict[str, Any]],
    ) -> List[ThreatModelDeltaResult]:
        """Run threat model diffing on all extraction deltas.

        Parameters
        ----------
        deltas : list[dict]
            Output from ``SecurityDeltaExtractor`` (or ``load_deltas()``).

        Returns
        -------
        list[ThreatModelDeltaResult]
        """
        results: List[ThreatModelDeltaResult] = []
        total = len(deltas)

        for idx, delta in enumerate(deltas, 1):
            sha = delta.get("commit_sha", "")
            fpath = delta.get("file", "")
            before_content = delta.get("before", "") or None
            after_content = delta.get("after", "") or None

            logger.info(
                "[%d/%d] Threat modelling %s @ %s",
                idx, total, fpath, sha[:8],
            )

            # Skip non-K8S content if configured
            if self.skip_non_k8s and not self._has_k8s_markers(
                before_content, after_content,
            ):
                continue

            # Build models and diff
            before_model = self._build_model(before_content)
            after_model = self._build_model(after_content)
            findings = self._diff_models(before_content, after_content)

            risk_delta = self._compute_risk_delta(findings)

            result = ThreatModelDeltaResult(
                commit_sha=sha,
                file_path=fpath,
                findings=[self._finding_to_dict(f) for f in findings],
                finding_count=len([
                    f for f in findings
                    if f.change_type != ChangeType.NONE
                ]),
                risk_delta=risk_delta,
                before_element_count=len(before_model.elements),
                after_element_count=len(after_model.elements),
                before_labels=sorted(before_model.all_labels),
                after_labels=sorted(after_model.all_labels),
            )
            results.append(result)

        return results

    @staticmethod
    def save_json(
        results: List[ThreatModelDeltaResult], output_path: str,
    ) -> None:
        """Save results to a JSON file."""
        data = [
            {
                "commit_sha": r.commit_sha,
                "file_path": r.file_path,
                "findings": r.findings,
                "finding_count": r.finding_count,
                "risk_delta": r.risk_delta,
                "before_element_count": r.before_element_count,
                "after_element_count": r.after_element_count,
                "before_labels": r.before_labels,
                "after_labels": r.after_labels,
            }
            for r in results
        ]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(
            "Saved %d threat model results to %s", len(data), output_path,
        )

    # ===================================================================
    # Model building (from pytm_mapper.py)
    # ===================================================================
    def _build_model(self, yaml_content: str | None) -> K8sModel:
        """Parse YAML and build a K8sModel from all documents.

        Steps:
          1. Parse all YAML documents.
          2. Collect NetworkPolicy docs for namespace context.
          3. Map each resource via ``_map_resource()``.
          4. For LoadBalancer/NodePort/Ingress, add ExternalEntity("Internet").
        """
        if not yaml_content:
            return K8sModel()

        docs = self._parse_yaml_documents(yaml_content)
        if not docs:
            return K8sModel()

        # Collect NetworkPolicies for label inference context
        net_policies = [d for d in docs if d.get("kind") == "NetworkPolicy"]

        model = K8sModel()
        has_internet_entity = False

        for doc in docs:
            element = self._map_resource(doc, net_policies)
            if element is None:
                continue

            model.elements.append(element)

            # Auto-create Internet ExternalEntity for public-facing resources
            if not has_internet_entity and self._needs_internet_entity(doc):
                model.elements.append(K8sElement(
                    kind="ExternalEntity",
                    name="Internet",
                    namespace="",
                    labels={"Public"},
                    source_resource="ExternalEntity",
                ))
                has_internet_entity = True

        return model

    @staticmethod
    def _parse_yaml_documents(yaml_content: str) -> list[dict]:
        """Parse multi-document YAML safely.  Returns non-None dicts."""
        if not yaml_content:
            return []
        docs: list[dict] = []
        try:
            for doc in yaml.safe_load_all(yaml_content):
                if isinstance(doc, dict) and doc.get("kind"):
                    docs.append(doc)
        except yaml.YAMLError:
            logger.debug("Failed to parse YAML content")
        return docs

    def _map_resource(
        self, doc: dict, namespace_policies: list[dict],
    ) -> K8sElement | None:
        """Map a single K8S resource dict to a K8sElement."""
        kind = doc.get("kind", "")
        pytm_kind = self._kind_map.get(kind)
        if pytm_kind is None:
            logger.debug("Skipping unmapped K8S kind: %s", kind)
            return None

        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")

        labels = self._infer_labels(doc, namespace_policies)
        properties: dict[str, Any] = {}

        # Extract kind-specific properties
        if kind == "Service":
            properties = self._extract_service_properties(doc)
        elif kind == "Ingress":
            properties = self._extract_ingress_properties(doc)
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            properties = self._extract_binding_properties(doc)
        elif kind == "NetworkPolicy":
            spec = doc.get("spec", {}) or {}
            properties["pod_selector"] = spec.get("podSelector", {})
            properties["policy_types"] = spec.get("policyTypes", [])
        elif kind in self._workload_kinds:
            spec = doc.get("spec", {}) or {}
            template = spec.get("template", {})
            if template:
                pod_labels = (
                    (template.get("metadata", {}) or {}).get("labels", {})
                    or {}
                )
                properties["pod_labels"] = pod_labels

        return K8sElement(
            kind=pytm_kind,
            name=name,
            namespace=namespace,
            labels=labels,
            source_resource=kind,
            properties=properties,
        )

    @staticmethod
    def _extract_service_properties(doc: dict) -> dict[str, Any]:
        """Extract properties specific to Service resources."""
        spec = doc.get("spec", {}) or {}
        svc_type = spec.get("type", "ClusterIP")
        selector = spec.get("selector", {}) or {}
        props: dict[str, Any] = {
            "service_type": svc_type,
            "selector": selector,
        }
        if svc_type in ("LoadBalancer", "NodePort"):
            props["source"] = "Internet"
            props["target"] = selector.get("app", "unknown")
        return props

    @staticmethod
    def _extract_ingress_properties(doc: dict) -> dict[str, Any]:
        """Extract properties specific to Ingress resources."""
        spec = doc.get("spec", {}) or {}
        rules = spec.get("rules", []) or []
        backends: list[str] = []
        for rule in rules:
            http = rule.get("http", {}) or {}
            for path_entry in http.get("paths", []) or []:
                backend = path_entry.get("backend", {}) or {}
                svc = backend.get("service", {}) or {}
                svc_name = svc.get("name", "")
                if svc_name:
                    backends.append(svc_name)
        return {"source": "Internet", "backends": backends}

    @staticmethod
    def _extract_binding_properties(doc: dict) -> dict[str, Any]:
        """Extract properties from ClusterRoleBinding / RoleBinding."""
        role_ref = doc.get("roleRef", {}) or {}
        subjects = doc.get("subjects", []) or []
        return {
            "role_name": role_ref.get("name", ""),
            "subjects": [
                {"kind": s.get("kind", ""), "name": s.get("name", "")}
                for s in subjects
            ],
        }

    def _needs_internet_entity(self, doc: dict) -> bool:
        """True if this resource introduces a public-facing dataflow."""
        kind = doc.get("kind", "")
        if kind == "Ingress":
            return True
        if kind == "Service":
            spec = doc.get("spec", {}) or {}
            return spec.get("type", "ClusterIP") in ("LoadBalancer", "NodePort")
        return False

    # ===================================================================
    # Label inference (from label_inference.py)
    # ===================================================================
    def _infer_labels(
        self,
        resource: dict[str, Any],
        namespace_policies: list[dict] | None = None,
    ) -> set[str]:
        """Infer security labels for a single parsed K8S resource."""
        kind = resource.get("kind", "")
        spec = resource.get("spec", {}) or {}
        metadata = resource.get("metadata", {}) or {}
        labels: set[str] = set()

        if kind in self._workload_kinds:
            labels |= self._infer_workload_labels(kind, spec)
            labels |= self._infer_network_policy_coverage(
                resource, namespace_policies,
            )
        elif kind == "Service":
            labels |= self._infer_service_labels(spec)
        elif kind == "Ingress":
            labels |= self._infer_ingress_labels(spec, metadata)
        elif kind == "Secret":
            labels.add("ContainsSecrets")
        elif kind == "ConfigMap":
            labels |= self._infer_configmap_labels(resource)
        elif kind in ("ClusterRole", "Role"):
            labels |= self._infer_rbac_labels(resource)
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            labels |= self._infer_binding_labels(resource)

        return labels

    def _infer_workload_labels(self, kind: str, spec: dict) -> set[str]:
        """Check securityContext and image pinning for workload resources."""
        labels: set[str] = set()

        pod_spec = self._extract_pod_spec(kind, spec)
        if not pod_spec:
            return labels

        containers = pod_spec.get("containers", []) or []
        init_containers = pod_spec.get("initContainers", []) or []
        all_containers = containers + init_containers

        # Pod-level security indicators
        if pod_spec.get("hostNetwork"):
            labels.add("AdminPath")
        if pod_spec.get("hostPID"):
            labels.add("AdminPath")
        if pod_spec.get("hostIPC"):
            labels.add("AdminPath")

        pod_sc = pod_spec.get("securityContext", {}) or {}
        if pod_sc.get("runAsUser") == 0:
            labels.add("AdminPath")
        if pod_sc.get("runAsNonRoot") is True:
            labels.add("ReadOnly")

        # Container-level checks
        for container in all_containers:
            sc = container.get("securityContext", {}) or {}
            if sc.get("privileged"):
                labels.add("AdminPath")
            if sc.get("runAsUser") == 0:
                labels.add("AdminPath")
            if sc.get("allowPrivilegeEscalation") is True:
                labels.add("AdminPath")
            if sc.get("readOnlyRootFilesystem"):
                labels.add("ReadOnly")

            # Capabilities
            caps = sc.get("capabilities", {}) or {}
            drop = [c.upper() for c in (caps.get("drop") or [])]
            if "ALL" in drop:
                labels.add("ReadOnly")
            add = [c.upper() for c in (caps.get("add") or [])]
            if any(c in add for c in ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE")):
                labels.add("AdminPath")

            # Image pinning
            image_label = self._check_image_pinning(
                container.get("image", ""),
            )
            if image_label:
                labels.add(image_label)

        # Secret volume mounts / env refs
        if self._has_secret_volume(pod_spec):
            labels.add("ContainsSecrets")
        if self._has_secret_env_ref(all_containers):
            labels.add("ContainsSecrets")

        # Service account
        sa = (
            pod_spec.get("serviceAccountName")
            or pod_spec.get("serviceAccount")
            or ""
        )
        if not sa or sa == "default":
            labels.add("Unauthenticated")
        else:
            labels.add("Authenticated")

        return labels

    @staticmethod
    def _extract_pod_spec(kind: str, spec: dict) -> dict | None:
        """Navigate to the pod spec from different workload types."""
        if kind == "Pod":
            return spec
        if kind == "CronJob":
            return (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            ) or None
        # Deployment, DaemonSet, StatefulSet, Job, ReplicaSet
        template = spec.get("template", {})
        return template.get("spec") if template else None

    @staticmethod
    def _infer_service_labels(spec: dict) -> set[str]:
        """Infer labels for a Service resource."""
        svc_type = spec.get("type", "ClusterIP")
        if svc_type in ("LoadBalancer", "NodePort"):
            return {"Public"}
        return {"Private"}

    @staticmethod
    def _infer_ingress_labels(spec: dict, metadata: dict) -> set[str]:
        """Infer labels for an Ingress resource."""
        labels: set[str] = {"Public"}
        annotations = metadata.get("annotations", {}) or {}

        tls = spec.get("tls")
        ssl_redirect = annotations.get(
            "nginx.ingress.kubernetes.io/ssl-redirect", "",
        )
        if tls or ssl_redirect.lower() == "true":
            labels.add("EncryptedInTransit")
        else:
            labels.add("UnencryptedInTransit")

        auth_type = annotations.get(
            "nginx.ingress.kubernetes.io/auth-type", "",
        )
        if auth_type:
            labels.add("Authenticated")
        else:
            labels.add("Unauthenticated")

        return labels

    def _infer_configmap_labels(self, resource: dict) -> set[str]:
        """Detect secrets stored in ConfigMap data fields."""
        data = resource.get("data", {}) or {}
        for key, val in data.items():
            if self._secret_pattern.search(key):
                return {"ContainsSecrets"}
            if isinstance(val, str) and self._secret_pattern.search(val):
                return {"ContainsSecrets"}
        return set()

    def _infer_rbac_labels(self, resource: dict) -> set[str]:
        """ClusterRole / Role -> AdminPath or ReadOnly."""
        labels: set[str] = set()
        rules = resource.get("rules", []) or []
        all_verbs: set[str] = set()

        for rule in rules:
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            if "*" in verbs or "*" in resources:
                labels.add("AdminPath")
                return labels
            all_verbs |= verbs

        if all_verbs and all_verbs <= self._readonly_verbs:
            labels.add("ReadOnly")
        elif all_verbs:
            labels.add("Authenticated")

        return labels

    @staticmethod
    def _infer_binding_labels(resource: dict) -> set[str]:
        """ClusterRoleBinding / RoleBinding -> AdminPath if cluster-admin."""
        role_ref = resource.get("roleRef", {}) or {}
        if role_ref.get("name") == "cluster-admin":
            return {"AdminPath"}
        return set()

    @staticmethod
    def _infer_network_policy_coverage(
        resource: dict, namespace_policies: list[dict] | None,
    ) -> set[str]:
        """Check if any NetworkPolicy governs this resource's pods."""
        if namespace_policies is None:
            return set()

        spec = resource.get("spec", {}) or {}
        template = spec.get("template", {})
        if template:
            pod_labels = (
                (template.get("metadata", {}) or {}).get("labels", {}) or {}
            )
        else:
            pod_labels = (
                (resource.get("metadata", {}) or {}).get("labels", {}) or {}
            )

        for policy in namespace_policies:
            policy_spec = policy.get("spec", {}) or {}
            selector = policy_spec.get("podSelector", {}) or {}
            match_labels = selector.get("matchLabels", {}) or {}

            if not match_labels:
                # Empty selector matches all pods in namespace
                return set()
            if all(pod_labels.get(k) == v for k, v in match_labels.items()):
                return set()

        return {"Unrestricted"}

    @staticmethod
    def _has_secret_volume(pod_spec: dict) -> bool:
        """True if the pod spec references a secret volume."""
        for vol in pod_spec.get("volumes", []) or []:
            if vol.get("secret"):
                return True
        return False

    @staticmethod
    def _has_secret_env_ref(containers: list[dict]) -> bool:
        """True if any container references a secret via envFrom or env."""
        for container in containers:
            for env_from in container.get("envFrom", []) or []:
                if env_from.get("secretRef"):
                    return True
            for env in container.get("env", []) or []:
                value_from = env.get("valueFrom", {}) or {}
                if value_from.get("secretKeyRef"):
                    return True
        return False

    @staticmethod
    def _check_image_pinning(image: str) -> str | None:
        """Return label for image pinning status.

        - ``VerifiedArtifact`` if digest-pinned (@sha256:...).
        - ``MutableArtifact`` if :latest or untagged.
        - None for specific tags (e.g. :v1.2.3).
        """
        if not image:
            return None
        if "@sha256:" in image:
            return "VerifiedArtifact"
        if ":latest" in image or ":" not in image.split("/")[-1]:
            return "MutableArtifact"
        return None

    # ===================================================================
    # Threat diffing (from threat_diff.py)
    # ===================================================================
    def _diff_models(
        self,
        before_yaml: str | None,
        after_yaml: str | None,
    ) -> list[ThreatFinding]:
        """Compare before and after YAML states and return threat findings.

        Handles:
          - before is None (new file): check NEW_UNHARDENED, ELEMENT_ADDED
          - after is None (deleted file): check BOUNDARY_REMOVED, ELEMENT_REMOVED
          - Both present: full diff
        """
        before_model = self._build_model(before_yaml)
        after_model = self._build_model(after_yaml)

        findings: list[ThreatFinding] = []

        if not before_model.elements and not after_model.elements:
            return findings

        # New file: only after state
        if not before_model.elements and after_model.elements:
            return self._detect_new_file(after_model)

        # Deleted file: only before state
        if before_model.elements and not after_model.elements:
            return self._detect_deleted_file(before_model)

        # Both present: full diff
        matched, added, removed = self._match_elements(
            before_model, after_model,
        )

        # Label flips on matched elements
        for before_elem, after_elem in matched:
            findings += self._detect_label_flips(before_elem, after_elem)

        # Boundary changes
        findings += self._detect_boundary_changes(before_model, after_model)

        # New risky combinations (only in after, not in before)
        findings += self._detect_risky_combinations(before_model, after_model)

        # Newly added unhardened processes
        for elem in added:
            if elem.kind == "Process" and not (
                elem.labels & self._hardening_labels
            ):
                findings.append(ThreatFinding(
                    change_type=ChangeType.NEW_UNHARDENED,
                    element_name=elem.name,
                    labels_before=[],
                    labels_after=sorted(elem.labels),
                    attack_class="AC9",
                    severity="MEDIUM",
                ))

        # Informational: added elements
        for elem in added:
            findings.append(ThreatFinding(
                change_type=ChangeType.ELEMENT_ADDED,
                element_name=elem.name,
                labels_before=[],
                labels_after=sorted(elem.labels),
                attack_class="",
                severity="INFO",
            ))

        # Informational: removed elements
        for elem in removed:
            findings.append(ThreatFinding(
                change_type=ChangeType.ELEMENT_REMOVED,
                element_name=elem.name,
                labels_before=sorted(elem.labels),
                labels_after=[],
                attack_class="",
                severity="INFO",
            ))

        return findings

    def _detect_new_file(self, model: K8sModel) -> list[ThreatFinding]:
        """Findings for a newly added file."""
        findings: list[ThreatFinding] = []

        # Unhardened processes
        for elem in model.processes():
            if not (elem.labels & self._hardening_labels):
                findings.append(ThreatFinding(
                    change_type=ChangeType.NEW_UNHARDENED,
                    element_name=elem.name,
                    labels_before=[],
                    labels_after=sorted(elem.labels),
                    attack_class="AC9",
                    severity="MEDIUM",
                ))

        # Risky combos on the new file
        for elem in model.elements:
            for combo, (ac, sev) in self._risky_combos.items():
                if combo <= elem.labels:
                    findings.append(ThreatFinding(
                        change_type=ChangeType.NEW_RISKY_COMBO,
                        element_name=elem.name,
                        labels_before=[],
                        labels_after=sorted(elem.labels),
                        attack_class=ac,
                        severity=sev,
                    ))

        # Informational: all added elements
        for elem in model.elements:
            findings.append(ThreatFinding(
                change_type=ChangeType.ELEMENT_ADDED,
                element_name=elem.name,
                labels_before=[],
                labels_after=sorted(elem.labels),
                attack_class="",
                severity="INFO",
            ))

        return findings

    @staticmethod
    def _detect_deleted_file(model: K8sModel) -> list[ThreatFinding]:
        """Findings for a deleted file."""
        findings: list[ThreatFinding] = []

        # Removed boundaries (NetworkPolicies)
        for elem in model.boundaries():
            if elem.source_resource == "NetworkPolicy":
                findings.append(ThreatFinding(
                    change_type=ChangeType.BOUNDARY_REMOVED,
                    element_name=elem.name,
                    labels_before=sorted(elem.labels),
                    labels_after=[],
                    attack_class="AC4",
                    severity="HIGH",
                ))

        # Informational: all removed elements
        for elem in model.elements:
            findings.append(ThreatFinding(
                change_type=ChangeType.ELEMENT_REMOVED,
                element_name=elem.name,
                labels_before=sorted(elem.labels),
                labels_after=[],
                attack_class="",
                severity="INFO",
            ))

        return findings

    def _detect_label_flips(
        self,
        before_elem: K8sElement,
        after_elem: K8sElement,
    ) -> list[ThreatFinding]:
        """Detect security label transitions on matched elements."""
        findings: list[ThreatFinding] = []

        for (secure, insecure), (ac, sev) in self._label_flip_ac.items():
            if secure in before_elem.labels and insecure in after_elem.labels:
                findings.append(ThreatFinding(
                    change_type=ChangeType.LABEL_FLIP,
                    element_name=after_elem.name,
                    labels_before=sorted(before_elem.labels),
                    labels_after=sorted(after_elem.labels),
                    attack_class=ac,
                    severity=sev,
                ))

        return findings

    @staticmethod
    def _detect_boundary_changes(
        before_model: K8sModel,
        after_model: K8sModel,
    ) -> list[ThreatFinding]:
        """Detect added/removed NetworkPolicy boundaries."""
        findings: list[ThreatFinding] = []

        before_boundaries = {
            (e.name, e.namespace)
            for e in before_model.boundaries()
            if e.source_resource == "NetworkPolicy"
        }
        after_boundaries = {
            (e.name, e.namespace)
            for e in after_model.boundaries()
            if e.source_resource == "NetworkPolicy"
        }

        for name, _ns in before_boundaries - after_boundaries:
            findings.append(ThreatFinding(
                change_type=ChangeType.BOUNDARY_REMOVED,
                element_name=name,
                labels_before=[],
                labels_after=[],
                attack_class="AC4",
                severity="HIGH",
            ))

        for name, _ns in after_boundaries - before_boundaries:
            findings.append(ThreatFinding(
                change_type=ChangeType.BOUNDARY_ADDED,
                element_name=name,
                labels_before=[],
                labels_after=[],
                attack_class="AC4",
                severity="LOW",
            ))

        return findings

    def _detect_risky_combinations(
        self,
        before_model: K8sModel,
        after_model: K8sModel,
    ) -> list[ThreatFinding]:
        """Detect new risky label combinations not present in before state."""
        findings: list[ThreatFinding] = []

        # Collect (element_key, combo) pairs from before model
        before_combos: set[tuple[str, frozenset[str]]] = set()
        for elem in before_model.elements:
            key = self._element_key(elem)
            for combo in self._risky_combos:
                if combo <= elem.labels:
                    before_combos.add((key, combo))

        # Check after model for new combos
        for elem in after_model.elements:
            key = self._element_key(elem)
            for combo, (ac, sev) in self._risky_combos.items():
                if combo <= elem.labels and (key, combo) not in before_combos:
                    findings.append(ThreatFinding(
                        change_type=ChangeType.NEW_RISKY_COMBO,
                        element_name=elem.name,
                        labels_before=[],
                        labels_after=sorted(elem.labels),
                        attack_class=ac,
                        severity=sev,
                    ))

        return findings

    @staticmethod
    def _match_elements(
        before_model: K8sModel,
        after_model: K8sModel,
    ) -> tuple[
        list[tuple[K8sElement, K8sElement]],
        list[K8sElement],
        list[K8sElement],
    ]:
        """Match elements between models by (name, namespace, source_resource).

        Returns
        -------
        tuple of (matched, added, removed)
        """
        before_map: dict[str, K8sElement] = {
            DeltaThreatModelDiffGenerator._element_key(e): e
            for e in before_model.elements
        }
        after_map: dict[str, K8sElement] = {
            DeltaThreatModelDiffGenerator._element_key(e): e
            for e in after_model.elements
        }

        matched: list[tuple[K8sElement, K8sElement]] = []
        added: list[K8sElement] = []
        removed: list[K8sElement] = []

        for key, after_elem in after_map.items():
            if key in before_map:
                matched.append((before_map[key], after_elem))
            else:
                added.append(after_elem)

        for key in before_map:
            if key not in after_map:
                removed.append(before_map[key])

        return matched, added, removed

    @staticmethod
    def _element_key(elem: K8sElement) -> str:
        """Composite key for matching elements across models."""
        return f"{elem.name}:{elem.namespace}:{elem.source_resource}"

    # ===================================================================
    # Helpers
    # ===================================================================
    @staticmethod
    def _has_k8s_markers(
        before: str | None, after: str | None,
    ) -> bool:
        """Return True if either content looks like K8S YAML."""
        for content in (before, after):
            if content and "apiVersion:" in content and "kind:" in content:
                return True
        return False

    def _compute_risk_delta(self, findings: list[ThreatFinding]) -> int:
        """Compute severity-weighted risk delta from threat findings.

        Positive values indicate a security regression.
        """
        risk_delta = 0
        for f in findings:
            if f.change_type == ChangeType.NONE:
                continue
            weight = self._severity_weights.get(f.severity, 0)
            if f.change_type == ChangeType.BOUNDARY_ADDED:
                risk_delta -= weight  # security improvement
            elif f.change_type in (
                ChangeType.ELEMENT_ADDED,
                ChangeType.ELEMENT_REMOVED,
            ):
                pass  # informational only
            else:
                risk_delta += weight  # security regression
        return risk_delta

    @staticmethod
    def _finding_to_dict(finding: ThreatFinding) -> Dict[str, Any]:
        """Serialise a ThreatFinding to a plain dict for JSON output."""
        change_type = finding.change_type
        return {
            "change_type": (
                change_type.value
                if hasattr(change_type, "value")
                else str(change_type)
            ),
            "element_name": finding.element_name,
            "labels_before": finding.labels_before,
            "labels_after": finding.labels_after,
            "attack_class": finding.attack_class,
            "severity": finding.severity,
        }

    # ===================================================================
    # Accessors for loaded configuration
    # ===================================================================
    @property
    def k8s_kind_map_config(self) -> dict:
        """Return the loaded k8s_kind_map.yaml contents."""
        return self._k8s_kind_map_cfg

    @property
    def threat_model_config(self) -> dict:
        """Return the loaded threat_model_config.yaml contents."""
        return self._threat_model_cfg


# Backward-compatible alias for existing imports.
PyTMGenerator = DeltaThreatModelDiffGenerator
