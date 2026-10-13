from app.scanner import analyze


def pod(name, labels, namespace='default'):
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':namespace,'labels':labels},'spec':{'containers':[{'name':'app','image':'alpine'}]}}


def policy(selector, namespace='default'):
    return {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'isolate','namespace':namespace},'spec':{'podSelector':selector,'policyTypes':['Ingress'],'ingress':[]}}


def test_policy_selects_matching_pods_only():
    result=analyze([pod('yes',{'app':'web'}),pod('no',{'app':'db'}),pod('wrong-ns',{'app':'web'},'other'),policy({'matchLabels':{'app':'web'}})])
    assert result['network_policies'][0]['selected_pods']==['Pod/default/yes']
    assert result['network_policies'][0]['reachability']=='not_computed'


def test_policy_selector_match_expressions():
    selector={'matchExpressions':[{'key':'tier','operator':'In','values':['frontend']},{'key':'debug','operator':'DoesNotExist'}]}
    result=analyze([pod('yes',{'tier':'frontend'}),pod('no',{'tier':'frontend','debug':'true'}),policy(selector)])
    assert result['network_policies'][0]['selected_pods']==['Pod/default/yes']


def test_empty_selector_matches_all_same_namespace():
    result=analyze([pod('a',{}),pod('b',{'x':'y'}),policy({})])
    assert len(result['network_policies'][0]['selected_pods'])==2
