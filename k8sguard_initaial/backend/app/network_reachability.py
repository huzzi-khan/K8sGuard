"""Conservative NetworkPolicy evaluation for *supplied Pods*.

Evaluates pod-to-pod TCP/UDP/SCTP traffic at an explicit numeric port. Both
source egress and destination ingress must allow it. This is a snapshot model:
CNI enforcement, Services, hostNetwork, ipBlock, named ports and missing pods
cannot be validated from YAML alone and are returned as unknown where relevant.
"""
from __future__ import annotations
from .module_a import _matches, namespace, oid


def _types(spec):
    return spec.get('policyTypes') if isinstance(spec.get('policyTypes'), list) else ['Ingress'] + (['Egress'] if 'egress' in spec else [])


def _namespace_labels(documents):
    return {o['metadata']['name']: o['metadata'].get('labels') or {} for o in documents if o['kind']=='Namespace'}


def _peer(peer, candidate, origin_namespace, namespace_labels):
    if not isinstance(peer, dict): return None
    if 'ipBlock' in peer: return None  # IP ranges require IP and routing context
    if not peer: return namespace(candidate)==origin_namespace
    has_ns='namespaceSelector' in peer
    has_pod='podSelector' in peer
    if not (has_ns or has_pod): return None
    if has_ns:
        labels=namespace_labels.get(namespace(candidate))
        if labels is None: return None
        if not _matches(labels, peer['namespaceSelector']): return False
    elif namespace(candidate)!=origin_namespace:
        return False
    if has_pod and not _matches(candidate['metadata'].get('labels') or {}, peer['podSelector']): return False
    return True


def _port_matches(ports, protocol, port):
    if ports is None or ports == []: return True
    uncertain=False
    for entry in ports:
        if not isinstance(entry,dict): uncertain=True;continue
        if entry.get('protocol','TCP') != protocol: continue
        p=entry.get('port')
        if p is None: return True
        if isinstance(p,str): uncertain=True;continue
        if isinstance(p,int) and p <= port <= entry.get('endPort',p): return True
    return None if uncertain else False


def _direction_allows(policies, pod, other, direction, port, protocol, labels):
    selected=[p for p in policies if namespace(p)==namespace(pod) and direction in _types(p['spec']) and
              _matches(pod['metadata'].get('labels') or {},p['spec'].get('podSelector') or {})]
    if not selected: return True, []
    unknown=False
    for policy in selected:
        for rule in policy['spec'].get(direction.lower()) or []:
            if not isinstance(rule,dict): unknown=True;continue
            port_ok=_port_matches(rule.get('ports'),protocol,port)
            if port_ok is False: continue
            peers=rule.get('to' if direction=='Egress' else 'from')
            if peers is None or peers == []: peer_ok=True
            else:
                results=[_peer(peer,other,namespace(policy),labels) for peer in peers]
                peer_ok=True if True in results else (None if None in results else False)
            if port_ok is True and peer_ok is True: return True,[oid(policy)]
            if port_ok is None or peer_ok is None: unknown=True
    return (None if unknown else False),[oid(p) for p in selected]


def evaluate_flows(documents, ports=(80,443), protocol='TCP'):
    """Return tri-state edges; 'allowed' means allowed *by supplied policies*, not proven network connectivity."""
    pods=[o for o in documents if o['kind']=='Pod']
    policies=[o for o in documents if o['kind']=='NetworkPolicy']
    labels=_namespace_labels(documents)
    flows=[]
    for source in pods:
        for target in pods:
            if source is target: continue
            for port in ports:
                eg,egp=_direction_allows(policies,source,target,'Egress',port,protocol,labels)
                ing,inp=_direction_allows(policies,target,source,'Ingress',port,protocol,labels)
                state='denied' if False in (eg,ing) else ('unknown' if None in (eg,ing) else 'allowed')
                flows.append({'source':oid(source),'target':oid(target),'protocol':protocol,'port':port,
                              'policy_result':state,'source_egress':eg,'destination_ingress':ing,
                              'relevant_policies':sorted(set(egp+inp)),
                              'interpretation':'Policy-only evaluation of supplied pods; not a connectivity test'})
    return flows
