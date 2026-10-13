from app.network_reachability import evaluate_flows

def pod(name,labels=None,ns='default'):
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':ns,'labels':labels or {}},'spec':{'containers':[{'name':'x','image':'alpine'}]}}

def netpol(name,selector,direction,rule,ns='default'):
    return {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':name,'namespace':ns},'spec':{'podSelector':{'matchLabels':selector},'policyTypes':[direction],direction.lower():rule}}

def flow(docs,src='a',dst='b',port=80):
    return next(x for x in evaluate_flows(docs,ports=(port,)) if x['source'].endswith('/'+src) and x['target'].endswith('/'+dst))

def test_default_unselected_allowed():
    assert flow([pod('a'),pod('b')])['policy_result']=='allowed'

def test_ingress_default_deny_blocks():
    docs=[pod('a'),pod('b',{'app':'db'}),netpol('deny',{'app':'db'},'Ingress',[])]
    assert flow(docs)['policy_result']=='denied'

def test_both_directions_required():
    docs=[pod('a',{'app':'client'}),pod('b',{'app':'db'}),netpol('deny-egress',{'app':'client'},'Egress',[]),
          netpol('allow-ingress',{'app':'db'},'Ingress',[{'from':[{'podSelector':{'matchLabels':{'app':'client'}}}]}])]
    assert flow(docs)['policy_result']=='denied'

def test_allow_rule_requires_matching_port():
    docs=[pod('a'),pod('b',{'app':'db'}),netpol('ports',{'app':'db'},'Ingress',[{'ports':[{'protocol':'TCP','port':443}]}])]
    assert flow(docs,port=80)['policy_result']=='denied'
    assert flow(docs,port=443)['policy_result']=='allowed'

def test_namespace_selector_missing_namespace_inventory_is_unknown():
    docs=[pod('a',ns='ns-a'),pod('b',{'app':'db'},'ns-b'),netpol('allow',{'app':'db'},'Ingress',[{'from':[{'namespaceSelector':{'matchLabels':{'team':'red'}}}]}],ns='ns-b')]
    assert flow(docs)['policy_result']=='unknown'

def test_additive_policies_allow_if_one_grants():
    docs=[pod('a'),pod('b',{'app':'db'}),netpol('deny',{'app':'db'},'Ingress',[]),netpol('allow',{'app':'db'},'Ingress',[{}])]
    assert flow(docs)['policy_result']=='allowed'
