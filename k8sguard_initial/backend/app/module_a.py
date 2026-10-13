"""Static, conservative Kubernetes security analysis for the FYP demonstration.

Claims are confined to capabilities supported by supplied objects. A reference edge
is not proof of exploitability; network reachability is intentionally not inferred.
"""
from __future__ import annotations
from typing import Any
import networkx as nx

WORKLOADS = {'Pod', 'Deployment', 'DaemonSet', 'StatefulSet', 'Job', 'CronJob', 'ReplicaSet'}
CLUSTER_KINDS = {'Namespace', 'ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition', 'Node', 'PersistentVolume', 'StorageClass', 'ClusterIssuer', 'ClusterSecretStore'}
REF_KEYS = {'issuerRef', 'secretStoreRef', 'storeRef', 'clusterIssuerRef'}

def namespace(o: dict) -> str:
    return o.get('metadata', {}).get('namespace', 'default')

def oid(o: dict) -> str:
    k = o['kind']; return f"{k}/{'cluster' if k in CLUSTER_KINDS else namespace(o)}/{o['metadata']['name']}"

def pod_spec(o: dict) -> dict:
    s = o.get('spec') or {}
    if o['kind'] == 'CronJob': s = ((s.get('jobTemplate') or {}).get('spec') or {})
    if o['kind'] != 'Pod': s = ((s.get('template') or {}).get('spec') or {})
    return s

def add_finding(fs: list, rule: str, severity: str, resource: str, description: str, evidence: dict, category='capability'):
    fs.append({'id': f'A-{len(fs)+1:04}', 'rule': rule, 'severity': severity, 'resource': resource,
               'description': description, 'evidence': evidence, 'category': category})

def inspect_workloads(docs: list[dict], g: nx.DiGraph, fs: list[dict]) -> None:
    for o in docs:
        if o['kind'] not in WORKLOADS: continue
        origin = oid(o); s = pod_spec(o)
        namespace_name = namespace(o)
        service_account = f"ServiceAccount/{namespace_name}/{s.get('serviceAccountName') or 'default'}"
        g.add_node(service_account, kind='ServiceAccount', label=service_account.rsplit('/', 1)[-1], namespace=namespace_name)
        g.add_edge(origin, service_account, relation='uses_service_account')
        for key in ('hostNetwork','hostPID','hostIPC'):
            if s.get(key) is True:
                add_finding(fs, f'POD_{key.upper()}', 'high', origin, f'{key} is enabled', {'field':key,'value':True})
        for vol in s.get('volumes') or []:
            if 'hostPath' in vol:
                add_finding(fs, 'POD_HOSTPATH', 'high', origin, 'Host path is mounted into the pod',
                            {'volume':vol.get('name'), 'path': (vol.get('hostPath') or {}).get('path')})
        if s.get('automountServiceAccountToken') is True:
            add_finding(fs, 'POD_TOKEN_AUTOMOUNT', 'info', origin, 'ServiceAccount token automount explicitly enabled', {'value':True})
        for container in (s.get('initContainers') or []) + (s.get('containers') or []) + (s.get('ephemeralContainers') or []):
            sc=container.get('securityContext') or {}; name=container.get('name','unnamed')
            if sc.get('privileged') is True:
                add_finding(fs, 'PRIVILEGED_CONTAINER', 'critical', origin, f'{name} runs privileged', {'container':name})
            if sc.get('allowPrivilegeEscalation') is True:
                add_finding(fs, 'PRIVILEGE_ESCALATION_ALLOWED', 'high', origin, f'{name} explicitly allows privilege escalation', {'container':name})
            caps=(sc.get('capabilities') or {}).get('add') or []
            dangerous=sorted(set(caps)&{'SYS_ADMIN','SYS_PTRACE','NET_ADMIN','DAC_READ_SEARCH','SYS_MODULE'})
            if dangerous:
                add_finding(fs, 'DANGEROUS_CAPABILITIES','high',origin,f'{name} adds high-impact Linux capabilities',{'container':name,'capabilities':dangerous})

def inspect_operator_references(docs: list[dict], g: nx.DiGraph, fs: list[dict]) -> list[dict]:
    """Known reference keys + kind/name resolution. Unresolved candidates are not confirmed edges."""
    known={oid(o):o for o in docs}; links=[]
    for o in docs:
        source=oid(o)
        def walk(x: Any, path: str):
            if isinstance(x, list):
                for i,v in enumerate(x): walk(v, f'{path}[{i}]')
            elif isinstance(x, dict):
                for k,v in x.items():
                    p=f'{path}.{k}' if path else k
                    if k in REF_KEYS and isinstance(v,dict) and isinstance(v.get('name'),str):
                        kind=v.get('kind')
                        if not kind:
                            kind={'secretStoreRef':'SecretStore','storeRef':'SecretStore','issuerRef':'Issuer'}.get(k)
                        if not kind: continue
                        refns=v.get('namespace',namespace(o))
                        possible=[f'{kind}/{refns}/{v["name"]}',f'{kind}/cluster/{v["name"]}']
                        target=next((id_ for id_ in possible if id_ in known),None)
                        record={'source':source,'reference_field':p,'kind':kind,'name':v['name'],
                                'target':target,'status':'resolved' if target else 'unresolved',
                                'cross_scope':bool(target and target.split('/')[1]!=namespace(o))}
                        links.append(record)
                        if target:
                            g.add_edge(source,target,relation='operator_reference',field=p,
                                       cross_namespace=record['cross_scope'],confidence='verified_object_reference')
                            if record['cross_scope']:
                                add_finding(fs,'CROSS_SCOPE_OPERATOR_REFERENCE','medium',source,
                                            'Custom resource references a resource in another scope',record, 'reference')
                    walk(v,p)
        if o['kind'] not in {'Role','ClusterRole','RoleBinding','ClusterRoleBinding'}:
            walk(o.get('spec') or {},'spec')
    return links

def _matches(labels: dict, selector: dict) -> bool:
    """Evaluate Kubernetes LabelSelector matchLabels and matchExpressions."""
    if not isinstance(selector, dict):
        return False
    labels = labels or {}
    if not all(labels.get(k) == v for k,v in (selector.get('matchLabels') or {}).items()):
        return False
    for expr in selector.get('matchExpressions') or []:
        key=expr.get('key'); op=expr.get('operator'); values=expr.get('values') or []
        exists=key in labels
        if op == 'In': ok=exists and labels[key] in values
        elif op == 'NotIn': ok=not exists or labels[key] not in values
        elif op == 'Exists': ok=exists
        elif op == 'DoesNotExist': ok=not exists
        else: return False
        if not ok: return False
    return True


def inspect_network_policies(docs: list[dict], fs: list[dict]) -> list[dict]:
    """Classify policy selection and isolation for supplied pod objects, not packet reachability.

    Offline manifests lack complete namespace/pod/service inventories and CNI behavior.
    A policy is isolation on its selected pods; allowed traffic is additive across policies.
    """
    pods=[o for o in docs if o['kind']=='Pod']
    policies=[]
    for o in docs:
        if o['kind'] != 'NetworkPolicy': continue
        s=o.get('spec') or {}; types=s.get('policyTypes')
        if types is None:
            types=['Ingress'] + (['Egress'] if 'egress' in s else [])
        if not isinstance(types,list): types=[]
        chosen=[oid(p) for p in pods if namespace(p)==namespace(o) and
                _matches((p.get('metadata') or {}).get('labels') or {},s.get('podSelector') or {})]
        record={'resource':oid(o),'namespace':namespace(o),'pod_selector':s.get('podSelector') or {},
                'policy_types':types,'ingress_rules':len(s.get('ingress') or []),
                'egress_rules':len(s.get('egress') or []),'selected_pods':chosen,
                'coverage':'supplied_pod_objects_only','reachability':'not_computed'}
        policies.append(record)
        if 'Ingress' in types and not s.get('ingress'):
            add_finding(fs,'NETPOL_DENY_INGRESS','info',oid(o),'Policy denies ingress to selected pods',record,'network')
        if 'Egress' in types and not s.get('egress'):
            add_finding(fs,'NETPOL_DENY_EGRESS','info',oid(o),'Policy denies egress from selected pods',record,'network')
    return policies

def derive_attack_paths(grants:list[dict], docs:list[dict], g:nx.DiGraph) -> list[dict]:
    """Evidence-backed candidate paths, not validated compromise chains."""
    paths=[]; seen=set(); workloads_by_sa={}
    for o in docs:
        if o['kind'] in WORKLOADS:
            s=pod_spec(o); sid=f"ServiceAccount/{namespace(o)}/{s.get('serviceAccountName') or 'default'}"
            workloads_by_sa.setdefault(sid,[]).append(oid(o))
    for grant in grants:
        subject=grant['subject']; verbs=set(grant['verbs']); resources=set(grant['resources'])
        read=bool(verbs&{'get','list','watch','*'}); write=bool(verbs&{'create','update','patch','*'})
        rules=[]
        if read and resources&{'secrets','*'} and not grant['resourceNames']:
            rules.append(('SECRET_READ_CAPABILITY','high','Read access to secrets can expose credentials'))
        if write and resources&{'clusterrolebindings','rolebindings','*'}:
            rules.append(('RBAC_BINDING_MUTATION_CAPABILITY','critical','Can alter access bindings; actual escalation depends on admission and escalation safeguards'))
        if verbs&{'create','*'} and resources&{'pods/exec','*'}:
            rules.append(('POD_EXEC_CAPABILITY','high','May execute in an authorized pod, subject to API controls'))
        for rule,sev,explanation in rules:
            key=(subject,grant['binding'],rule,grant['scope'])
            if key in seen:continue
            seen.add(key)
            for workload in workloads_by_sa.get(subject,[]) or [None]:
                ids=([workload] if workload else [])+[subject,grant['binding'],grant['role']]
                if not all(g.has_edge(a,b) for a,b in zip(ids,ids[1:])):continue
                paths.append({'id':f'P-{len(paths)+1:03}','rule':rule,'severity':sev,'nodes':ids,
                              'scope':grant['scope'],'classification':'capability_path',
                              'description':explanation,'evidence':{'verbs':grant['verbs'],'resources':grant['resources']}})
    return paths
