import ast
import csv
import json
import random

import pytest

from backend.app.datasets.core import ROOT, load_split
from backend.app.transformations.registry import transform, applicable
from backend.app.validation.checks import validate
from backend.app.environment.securecode import SecureCodeEnv
from training.cross_validate import check_partitions
from training.fit import fit
from training.evaluate import rollout


def test_original_labels_and_source_preserved():
    repo=ROOT/'datasets/raw/BenchmarkPython'
    labels={r[0]:r for r in csv.reader(l for l in (repo/'expectedresults-0.1.csv').read_text().splitlines() if not l.startswith('#'))}
    records=load_split('all')
    assert len(records)==len({r['id'] for r in records})==454
    for r in records:
        official=labels[r['id']]
        assert r['official_label']==official[2]
        assert r['cwe']==int(official[3])
        assert r['code']==(repo/r['source']).read_text()


@pytest.mark.parametrize('cwe,action,count',[(89,0,5),(614,5,22),(330,6,18)])
def test_real_coverage_and_properties(cwe,action,count):
    eligible=[]
    for r in load_split('all'):
        if r['cwe']!=cwe:
            continue
        result=transform(r['code'],action)
        if result['status']=='proposed':
            eligible.append(r)
            assert r['vulnerable']
            cert=validate(r['code'],result['code'],action)
            assert cert['security_verified'] and not cert['functional_verified']
            assert transform(result['code'],action)['status']=='incompatible'
            assert not validate(r['code'],result['code']+'\nraise RuntimeError()',action)['security_verified']
        if not r['vulnerable']:
            assert result['code']==r['code']
    assert len(eligible)==count


def test_fold_isolation_and_once_only_testing():
    report=json.loads((ROOT/'datasets/manifests/folds.json').read_text())
    check_partitions(report['folds'],load_split('all'))
    assert all(f['test']['treatable']>=9 for f in report['folds'])
    altered=json.loads(json.dumps(report['folds']))
    altered[0]['train']['ids'].append(altered[0]['test']['ids'][0])
    with pytest.raises(AssertionError):
        check_partitions(altered,load_split('all'))


def test_safe_bytes_harness():
    # Trusted stdlib harness only; no benchmark/user code executes.
    value=random.SystemRandom().randbytes(32)
    assert isinstance(value,bytes) and len(value)==32
    assert random.SystemRandom.getrandbits.__module__=='random'


def test_cookie_property_harness():
    # Python's cookie encoder verifies attributes without starting a web app.
    from http.cookies import SimpleCookie
    cookie=SimpleCookie()
    cookie['session']='test'
    cookie['session']['secure']=True
    cookie['session']['httponly']=True
    assert 'Secure' in cookie.output() and 'HttpOnly' in cookie.output()


def test_reject_other_random_contracts():
    for expression in ('random.randbytes(4)','random.getrandbits(32)','random.random()'):
        code=f'import random\nvalue = {expression}\n'
        assert transform(code,6)['status']=='incompatible'
    assert transform('import random\nrandom = attacker\nvalue = random.randbytes(32)',6)['status']=='incompatible'


def test_multiple_transformations_validate_separately():
    # Synthetic unit fixture, never added to the experimental corpus.
    code='''from flask import make_response
import random
RESPONSE = ""
RESPONSE = make_response(RESPONSE)
RESPONSE.set_cookie("session", "value", secure=False)
value = random.randbytes(32)
'''
    env=SecureCodeEnv([{'code':code,'vulnerable':True}])
    env.reset()
    for action in (5,3,6,3,4):
        env.step(action)
    assert env.security_verified and env.validated_changes==2
    assert not applicable(env.code)


def test_expanded_observation_has_no_official_label():
    record=next(r for r in load_split('all') if r['cwe']==330 and applicable(r['code']))
    original=SecureCodeEnv([record])
    altered=SecureCodeEnv([{**record,'vulnerable':False,'id':'other','cwe':1}])
    assert original.reset(seed=42)[0]==altered.reset(seed=42)[0]
