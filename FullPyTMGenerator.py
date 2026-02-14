#!/usr/bin/env python3
"""FullPyTMGenerator.py -- Native pytm execution over a full Kubernetes manifest snapshot.

This script builds a single threat model from Kubernetes YAML files in a repository
and runs native pytm threat resolution (`TM.check()` + `TM.resolve()`).

It is complementary to `DeltaThreatModelDiffGenerator.py`:
  - `DeltaThreatModelDiffGenerator.py` is a custom delta-oriented macro detector.
  - `FullPyTMGenerator.py` is a full-snapshot native pytm runner.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

LOG = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
PYTM_VENDOR_DIR = BASE_DIR / "data" / "pytm"
if PYTM_VENDOR_DIR.exists() and str(PYTM_VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(PYTM_VENDOR_DIR))

from pytm import (  # type: ignore  # noqa: E402
    Action,
    Actor,
    Boundary,
    Dataflow,
    Datastore,
    ExternalEntity,
    Process,
    TM,
)


WORKLOAD_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "Pod",
}

DATASTORE_KINDS = {"Secret", "ConfigMap", "PersistentVolumeClaim"}


@dataclass
class WorkloadRef:
    namespace: str
    name: str
    labels: Dict[str, str]
    element: Process
    pod_spec: Dict[str, Any]


@dataclass
class ServiceRef:
    namespace: str
    name: str
    selector: Dict[str, str]
    service_type: str
    ports: List[Dict[str, Any]]
    element: Process


class FullPyTMGenerator:
    """Create and resolve a native pytm model from a full repo snapshot."""

    def __init__(
        self,
        repo_path: str,
        include_extensions: Optional[Iterable[str]] = None,
        max_files: Optional[int] = None,
    ) -> None:
        self.repo_path = Path(repo_path)
        self.include_extensions = set(include_extensions or {".yaml", ".yml"})
        self.max_files = max_files
        self._boundaries: Dict[str, Boundary] = {}
        self._elements: Dict[Tuple[str, str, str], Any] = {}
        self._workloads: List[WorkloadRef] = []
        self._services: List[ServiceRef] = []
        self._ingresses: List[Dict[str, Any]] = []
        self._internet: Optional[ExternalEntity] = None

    def run(self) -> Dict[str, Any]:
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository path not found: {self.repo_path}")

        TM.reset()
        tm = TM("Full Kubernetes Threat Model")
        tm.description = f"Native pytm model generated from repository snapshot: {self.repo_path}"
        tm.onDuplicates = Action.IGNORE
        tm.isOrdered = True
        tm.mergeResponses = True

        files = list(self._iter_manifest_files())
        docs_seen = 0
        for manifest_path in files:
            for doc in self._load_documents(manifest_path):
                docs_seen += 1
                self._register_resource(doc)

        self._ensure_internet_entity()
        self._build_service_to_workload_flows()
        self._build_ingress_flows()
        self._build_public_service_flows()
        self._build_workload_to_datastore_flows()

        tm.check()
        tm.resolve()

        findings = [self._finding_to_dict(f) for f in tm.findings]
        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "generated_at": datetime.now().isoformat(),
            "repo_path": str(self.repo_path),
            "files_scanned": len(files),
            "documents_parsed": docs_seen,
            "element_count": len(TM._elements),
            "flow_count": len(TM._flows),
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "findings": findings,
        }

    @staticmethod
    def save_json(result: Dict[str, Any], output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        LOG.info("Saved native pytm full-snapshot results to %s", output_path)

    def _iter_manifest_files(self) -> Iterable[Path]:
        count = 0
        for path in self.repo_path.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in self.include_extensions:
                continue
            yield path
            count += 1
            if self.max_files and count >= self.max_files:
                return

    @staticmethod
    def _load_documents(path: Path) -> List[Dict[str, Any]]:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        if "apiVersion:" not in raw or "kind:" not in raw:
            return []

        docs: List[Dict[str, Any]] = []
        try:
            for doc in yaml.safe_load_all(raw):
                if isinstance(doc, dict) and doc.get("kind"):
                    docs.append(doc)
        except yaml.YAMLError:
            return []
        return docs

    def _namespace_boundary(self, namespace: str) -> Boundary:
        ns = namespace or "default"
        if ns not in self._boundaries:
            self._boundaries[ns] = Boundary(f"namespace:{ns}")
        return self._boundaries[ns]

    def _register_resource(self, doc: Dict[str, Any]) -> None:
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        key = (kind, namespace, name)
        if key in self._elements:
            return

        if kind in WORKLOAD_KINDS:
            element = Process(f"{namespace}/{name}")
            element.inBoundary = self._namespace_boundary(namespace)
            self._apply_workload_controls(element, doc)
            self._elements[key] = element

            pod_spec = self._extract_pod_spec(kind, doc.get("spec", {}) or {})
            labels = self._extract_workload_labels(kind, doc)
            self._workloads.append(
                WorkloadRef(
                    namespace=namespace,
                    name=name,
                    labels=labels,
                    element=element,
                    pod_spec=pod_spec,
                )
            )
            return

        if kind == "Service":
            element = Process(f"{namespace}/{name}")
            element.inBoundary = self._namespace_boundary(namespace)
            spec = doc.get("spec", {}) or {}
            self._elements[key] = element
            self._services.append(
                ServiceRef(
                    namespace=namespace,
                    name=name,
                    selector=spec.get("selector", {}) or {},
                    service_type=spec.get("type", "ClusterIP"),
                    ports=spec.get("ports", []) or [],
                    element=element,
                )
            )
            return

        if kind == "Ingress":
            element = Process(f"{namespace}/{name}")
            element.inBoundary = self._namespace_boundary(namespace)
            self._elements[key] = element
            self._ingresses.append(doc)
            return

        if kind in DATASTORE_KINDS:
            ds = Datastore(f"{namespace}/{name}")
            ds.inBoundary = self._namespace_boundary(namespace)
            ds.controls.isEncryptedAtRest = True if kind == "Secret" else False
            self._elements[key] = ds
            return

        if kind == "ServiceAccount":
            actor = Actor(f"{namespace}/{name}")
            actor.inBoundary = self._namespace_boundary(namespace)
            self._elements[key] = actor

    def _ensure_internet_entity(self) -> None:
        if self._internet is None:
            self._internet = ExternalEntity("Internet")

    @staticmethod
    def _extract_workload_labels(kind: str, doc: Dict[str, Any]) -> Dict[str, str]:
        metadata = doc.get("metadata", {}) or {}
        spec = doc.get("spec", {}) or {}
        if kind == "Pod":
            return metadata.get("labels", {}) or {}
        if kind == "CronJob":
            return (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("metadata", {})
                .get("labels", {})
            ) or {}
        return (spec.get("template", {}).get("metadata", {}).get("labels", {})) or {}

    @staticmethod
    def _extract_pod_spec(kind: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        if kind == "Pod":
            return spec
        if kind == "CronJob":
            return (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            ) or {}
        return (spec.get("template", {}).get("spec", {})) or {}

    @staticmethod
    def _apply_workload_controls(element: Process, doc: Dict[str, Any]) -> None:
        kind = doc.get("kind", "")
        spec = doc.get("spec", {}) or {}
        pod_spec = FullPyTMGenerator._extract_pod_spec(kind, spec)
        containers = (pod_spec.get("containers", []) or []) + (
            pod_spec.get("initContainers", []) or []
        )

        is_privileged = False
        has_root = False
        for c in containers:
            sc = c.get("securityContext", {}) or {}
            if sc.get("privileged") is True or sc.get("allowPrivilegeEscalation") is True:
                is_privileged = True
            if sc.get("runAsUser") == 0:
                has_root = True

        run_as_non_root = (pod_spec.get("securityContext", {}) or {}).get("runAsNonRoot") is True
        element.controls.isHardened = run_as_non_root and not is_privileged and not has_root
        element.controls.hasAccessControl = bool(
            pod_spec.get("serviceAccountName") and pod_spec.get("serviceAccountName") != "default"
        )
        element.usesEnvironmentVariables = any((c.get("env") or c.get("envFrom")) for c in containers)

    def _service_protocol(self, service: ServiceRef) -> Tuple[str, int, bool]:
        ports = service.ports or []
        first = ports[0] if ports else {}
        port = int(first.get("port", 0) or 0)
        if port == 443:
            return "HTTPS", port, True
        return "HTTP", port, False

    def _build_service_to_workload_flows(self) -> None:
        for svc in self._services:
            if not svc.selector:
                continue
            protocol, port, encrypted = self._service_protocol(svc)
            for wl in self._workloads:
                if wl.namespace != svc.namespace:
                    continue
                if all(wl.labels.get(k) == v for k, v in svc.selector.items()):
                    flow = Dataflow(
                        svc.element,
                        wl.element,
                        f"service:{svc.name} -> workload:{wl.name}",
                    )
                    flow.protocol = protocol
                    if port > 0:
                        flow.dstPort = port
                    flow.controls.isEncrypted = encrypted

    def _build_ingress_flows(self) -> None:
        if not self._internet:
            return
        for ing in self._ingresses:
            metadata = ing.get("metadata", {}) or {}
            spec = ing.get("spec", {}) or {}
            ns = metadata.get("namespace", "default")
            tls_enabled = bool(spec.get("tls"))

            backend_names: List[str] = []
            for rule in spec.get("rules", []) or []:
                http = rule.get("http", {}) or {}
                for p in http.get("paths", []) or []:
                    svc = ((p.get("backend", {}) or {}).get("service", {}) or {})
                    svc_name = svc.get("name")
                    if svc_name:
                        backend_names.append(svc_name)

            for svc_name in sorted(set(backend_names)):
                service_elem = self._elements.get(("Service", ns, svc_name))
                if not service_elem:
                    continue
                flow = Dataflow(
                    self._internet,
                    service_elem,
                    f"internet -> ingress-backend:{ns}/{svc_name}",
                )
                flow.protocol = "HTTPS" if tls_enabled else "HTTP"
                flow.dstPort = 443 if tls_enabled else 80
                flow.controls.isEncrypted = tls_enabled

    def _build_public_service_flows(self) -> None:
        if not self._internet:
            return
        for svc in self._services:
            if svc.service_type not in {"LoadBalancer", "NodePort"}:
                continue
            protocol, port, encrypted = self._service_protocol(svc)
            flow = Dataflow(
                self._internet,
                svc.element,
                f"internet -> service:{svc.namespace}/{svc.name}",
            )
            flow.protocol = protocol
            if port > 0:
                flow.dstPort = port
            flow.controls.isEncrypted = encrypted

    def _build_workload_to_datastore_flows(self) -> None:
        for wl in self._workloads:
            refs = self._collect_secret_configmap_refs(wl.pod_spec)
            for kind, name in sorted(refs):
                datastore = self._elements.get((kind, wl.namespace, name))
                if not datastore:
                    continue
                flow = Dataflow(
                    wl.element,
                    datastore,
                    f"workload:{wl.name} -> {kind.lower()}:{name}",
                )
                flow.protocol = "K8S_API"
                flow.controls.isEncrypted = True

    @staticmethod
    def _collect_secret_configmap_refs(pod_spec: Dict[str, Any]) -> set[Tuple[str, str]]:
        refs: set[Tuple[str, str]] = set()
        containers = (pod_spec.get("containers", []) or []) + (
            pod_spec.get("initContainers", []) or []
        )

        for vol in pod_spec.get("volumes", []) or []:
            if (vol.get("secret") or {}).get("secretName"):
                refs.add(("Secret", vol["secret"]["secretName"]))
            if (vol.get("configMap") or {}).get("name"):
                refs.add(("ConfigMap", vol["configMap"]["name"]))

        for c in containers:
            for env_from in c.get("envFrom", []) or []:
                if (env_from.get("secretRef") or {}).get("name"):
                    refs.add(("Secret", env_from["secretRef"]["name"]))
                if (env_from.get("configMapRef") or {}).get("name"):
                    refs.add(("ConfigMap", env_from["configMapRef"]["name"]))
            for env in c.get("env", []) or []:
                value_from = env.get("valueFrom", {}) or {}
                if (value_from.get("secretKeyRef") or {}).get("name"):
                    refs.add(("Secret", value_from["secretKeyRef"]["name"]))
                if (value_from.get("configMapKeyRef") or {}).get("name"):
                    refs.add(("ConfigMap", value_from["configMapKeyRef"]["name"]))

        return refs

    @staticmethod
    def _finding_to_dict(finding: Any) -> Dict[str, Any]:
        return {
            "id": getattr(finding, "id", ""),
            "threat_id": getattr(finding, "threat_id", ""),
            "severity": getattr(finding, "severity", ""),
            "target": getattr(finding, "target", ""),
            "description": getattr(finding, "description", ""),
            "details": getattr(finding, "details", ""),
            "condition": getattr(finding, "condition", ""),
            "mitigations": getattr(finding, "mitigations", ""),
            "references": getattr(finding, "references", ""),
            "element_type": (
                type(getattr(finding, "element", None)).__name__
                if getattr(finding, "element", None) is not None
                else ""
            ),
        }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run native pytm on a full Kubernetes manifest snapshot."
    )
    parser.add_argument(
        "--repo-path",
        default=str(BASE_DIR / "data" / "kubernetes"),
        help="Path to the repository or manifest root directory.",
    )
    parser.add_argument(
        "--output-json",
        default=str(BASE_DIR / "output" / "full_pytm_results.json"),
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Optional cap on the number of manifest files to scan.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    output_path = Path(args.output_json)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    gen = FullPyTMGenerator(
        repo_path=args.repo_path,
        max_files=args.max_files,
    )
    result = gen.run()
    gen.save_json(result, str(output_path))
    LOG.info(
        "Native pytm complete: files=%d docs=%d elements=%d flows=%d findings=%d",
        result["files_scanned"],
        result["documents_parsed"],
        result["element_count"],
        result["flow_count"],
        result["finding_count"],
    )


if __name__ == "__main__":
    main()
