"""Read-only, offline Kubernetes manifest security analyzer (initial iteration)."""
from __future__ import annotations
from collections import defaultdict
from typing import Any
import networkx as nx
import yaml
from .rbac import collect_effective_access, grant_findings
from .frameworks import annotate
from .module_a import inspect_workloads, inspect_operator_references, inspect_network_policies, derive_attack_paths

MAX_DOCUMENTS = 100
MAX_BYTES = 2 * 1024 * 1024


def parse_manifests(content: bytes) -> list[dict[str, Any]]:
    if len(content) > MAX_BYTES:
        raise ValueError("Manifest exceeds the 2 MiB upload limit")
    try:
        parsed = list(yaml.safe_load_all(content.decode("utf-8")))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ValueError("Invalid YAML or UTF-8 encoding") from exc
    docs = [d for d in parsed if d is not None]
    if not docs or len(docs) > MAX_DOCUMENTS:
        raise ValueError("Provide 1–100 nonempty YAML documents")
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict) or not all(isinstance(doc.get(k), str) and doc[k] for k in ("apiVersion", "kind")):
            raise ValueError(f"Document {i+1} requires apiVersion and kind")
        if not isinstance(doc.get("metadata"), dict) or not isinstance(doc["metadata"].get("name"), str):
            raise ValueError(f"Document {i+1} requires metadata.name")
    return docs


def identity(obj: dict) -> str:
    m = obj["metadata"]
    return f'{obj["kind"]}/{"cluster" if obj["kind"] in ("ClusterRole", "ClusterRoleBinding", "Namespace", "CustomResourceDefinition") else m.get("namespace", "default")}/{m["name"]}'


def analyze(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """Initial static rules and RBAC bindings graph, not a complete attack-path engine."""
    g = nx.DiGraph()
    findings: list[dict[str, Any]] = []
    def add_finding(rule, severity, obj, description):
        findings.append({"id": f"F-{len(findings)+1:03}", "rule": rule, "severity": severity,
                         "resource": identity(obj), "description": description,
                         "evidence": {"kind": obj["kind"], "name": obj["metadata"]["name"]}})
    for o in docs:
        node = identity(o)
        g.add_node(node, label=o["metadata"]["name"], kind=o["kind"], namespace="cluster" if o["kind"] in ("ClusterRole", "ClusterRoleBinding", "Namespace", "CustomResourceDefinition") else o["metadata"].get("namespace", "default"))
        kind = o["kind"]
        if kind in ("Role", "ClusterRole"):
            for rule in o.get("rules") or []:
                verbs = rule.get("verbs") or []
                resources = rule.get("resources") or []
                if "*" in verbs or "*" in resources:
                    add_finding("RBAC_WILDCARD", "high", o, "Role grants wildcard API verbs or resources")
                if "secrets" in resources and any(v in verbs for v in ("get", "list", "watch", "*")):
                    add_finding("RBAC_SECRET_READ", "high", o, "Role can read Kubernetes Secrets")
        if kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"):
            spec = o.get("spec") or {}
            if kind == "CronJob": spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
            elif kind == "Job": spec = ((spec.get("template") or {}).get("spec") or {})
            elif kind != "Pod": spec = ((spec.get("template") or {}).get("spec") or {})
            for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
                if (container.get("securityContext") or {}).get("privileged") is True:
                    add_finding("PRIVILEGED_CONTAINER", "critical", o, f'Container {container.get("name", "unnamed")} is privileged')
            sa = spec.get("serviceAccountName", "default")
            sa_id = f'ServiceAccount/{o["metadata"].get("namespace", "default")}/{sa}'
            g.add_node(sa_id, kind="ServiceAccount", label=sa)
            g.add_edge(node, sa_id, relation="uses_service_account")
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            role = o.get("roleRef") or {}
            target = f'{role.get("kind", "Role")}/{"cluster" if role.get("kind")=="ClusterRole" else o["metadata"].get("namespace", "default")}/{role.get("name", "unknown")}'
            g.add_node(target, kind=role.get("kind", "Role"), label=role.get("name", "unknown"))
            g.add_edge(node, target, relation="grants_role")
            for subject in o.get("subjects") or []:
                ns = subject.get("namespace", o["metadata"].get("namespace", "default"))
                sub_id = f'{subject.get("kind", "Unknown")}/{ns}/{subject.get("name", "unknown")}'
                g.add_node(sub_id, kind=subject.get("kind", "Unknown"), label=subject.get("name", "unknown"))
                g.add_edge(sub_id, node, relation="bound_by")
    effective_permissions, unresolved = collect_effective_access(docs, g)
    findings.extend(grant_findings(effective_permissions))
    inspect_workloads(docs, g, findings)
    reference_links = inspect_operator_references(docs, g, findings)
    network_policies = inspect_network_policies(docs, findings)
    attack_paths = derive_attack_paths(effective_permissions, docs, g)
    return annotate({"effective_permissions": effective_permissions, "unresolved_references": unresolved, "resources": len(docs), "nodes": [{"id": n, **attrs} for n, attrs in g.nodes(data=True)],
            "edges": [{"source": u, "target": v, **attrs} for u, v, attrs in g.edges(data=True)],
            "findings": findings, "attack_paths": attack_paths, "operator_references": reference_links, "network_policies": network_policies,
            "limitations": ["Initial rules only: findings are capabilities, not proven exploit paths.",
                             "Offline RBAC only covers explicit ServiceAccount subjects and supplied roles; unresolved references are returned.",
                             "NetworkPolicy inventory is implemented, but full selector-based network reachability is not; attack paths are capability paths, not demonstrated exploits.",
                             "Operator references use a finite set of known field names and only confirm targets present in the supplied snapshot.",
                             "Live Kubernetes collection and unrestricted schema-agnostic CRD discovery are not implemented.",]})
