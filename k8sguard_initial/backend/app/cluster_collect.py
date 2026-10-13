"""Explicit, read-only snapshot collector; run on a trusted developer machine.

No kubectl invocation and no credentials sent to a browser. Kubernetes RBAC of the
calling identity governs which resources can be seen. Collection failures are
reported, not silently interpreted as security passes.
"""
from __future__ import annotations
import json
from pathlib import Path


def collect_snapshot(context: str | None = None) -> tuple[list[dict], list[str]]:
    try:
        from kubernetes import client, config
    except ImportError as exc:
        raise RuntimeError('Install backend requirements including kubernetes') from exc
    config.load_kube_config(context=context)
    api=client.ApiClient()
    core=client.CoreV1Api(api)
    apps=client.AppsV1Api(api)
    batch=client.BatchV1Api(api)
    networking=client.NetworkingV1Api(api)
    rbac=client.RbacAuthorizationV1Api(api)
    calls={
      'pods':core.list_pod_for_all_namespaces,
      'namespaces':core.list_namespace,
      'serviceaccounts':core.list_service_account_for_all_namespaces,
      'deployments':apps.list_deployment_for_all_namespaces,
      'daemonsets':apps.list_daemon_set_for_all_namespaces,
      'statefulsets':apps.list_stateful_set_for_all_namespaces,
      'jobs':batch.list_job_for_all_namespaces,
      'cronjobs':batch.list_cron_job_for_all_namespaces,
      'roles':rbac.list_role_for_all_namespaces,
      'clusterroles':rbac.list_cluster_role,
      'rolebindings':rbac.list_role_binding_for_all_namespaces,
      'clusterrolebindings':rbac.list_cluster_role_binding,
      'networkpolicies':networking.list_network_policy_for_all_namespaces,
    }
    resources=[]; errors=[]
    for name,call in calls.items():
        try:
            response=call(_request_timeout=20)
            obj=api.sanitize_for_serialization(response)
            for item in obj.get('items',[]):
                if isinstance(item,dict) and all(k in item for k in ('kind','metadata','apiVersion')):
                    resources.append(item)
                elif isinstance(item,dict):
                    kind_map={'pods':'Pod','namespaces':'Namespace','serviceaccounts':'ServiceAccount','deployments':'Deployment',
                    'daemonsets':'DaemonSet','statefulsets':'StatefulSet','jobs':'Job','cronjobs':'CronJob','roles':'Role',
                    'clusterroles':'ClusterRole','rolebindings':'RoleBinding','clusterrolebindings':'ClusterRoleBinding',
                    'networkpolicies':'NetworkPolicy'}
                    item['kind']=kind_map[name];item['apiVersion']='v1' if name in ('pods','namespaces','serviceaccounts') else 'apps/v1'
                    resources.append(item)
        except Exception as exc:
            errors.append(f'{name}: {type(exc).__name__}: {exc}')
    return resources,errors


def main():
    import argparse
    from .scanner import analyze
    parser=argparse.ArgumentParser(description='Read-only K8sGuard Kubernetes scanner')
    parser.add_argument('--context',help='Explicit kubeconfig context; defaults to current context')
    parser.add_argument('--output',default='k8sguard-scan.json')
    parser.add_argument('--max-resources',type=int,default=10000)
    args=parser.parse_args()
    resources,errors=collect_snapshot(args.context)
    if not resources:
        raise SystemExit('No resources collected. Check kubeconfig context and read permissions. Errors: '+str(errors))
    if len(resources)>args.max_resources:raise SystemExit('Snapshot exceeds resource safety limit')
    result=analyze(resources)
    result['collection_errors']=errors
    result['source']='live_cluster_snapshot'
    result['limitations'].append('Snapshot may be incomplete due to RBAC, collection errors, pagination, or unsupported resource kinds; custom resources are not collected by this command.')
    destination=Path(args.output)
    destination.write_text(json.dumps(result,indent=2,default=str),encoding='utf8')
    print(f'Wrote {destination} with {len(resources)} resources; {len(errors)} collection errors')
    for error in errors:print('WARNING:',error)

if __name__=='__main__': main()
