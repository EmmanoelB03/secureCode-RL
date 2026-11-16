import ast
import json
import sqlite3

import numpy as np
import pytest
from gymnasium.utils.env_checker import check_env

from backend.app.agents.qlearning import QLearningAgent
from backend.app.analysis.static import analyze, bandit_scan
from backend.app.datasets.core import ROOT, load_split, flow_group
from backend.app.environment.securecode import SecureCodeEnv
from backend.app.transformations.sql import QUERY, transform
from backend.app.validation.checks import validate


@pytest.fixture
def real():
    return next(r for r in load_split('train') if r['id'] == 'BenchmarkTest00099')


def test_origin_and_disjoint_groups():
    parts = [load_split(s) for s in ('train','validation','test')]
    assert sum(map(len, parts)) == 454
    for i in range(3):
        for j in range(i):
            assert not {r['group'] for r in parts[i]} & {r['group'] for r in parts[j]}
    for row in sum(parts, []):
        assert row['official_label'] == str(row['vulnerable']).lower()


def test_sql_real_and_independent_validation(real):
    fixed = transform(real['code'], 0)
    assert fixed['status'] == 'proposed'
    assert validate(real['code'], fixed['code'])['security_verified']
    assert not validate(real['code'], fixed['code'])['functional_verified']
    assert not analyze(fixed['code'])['alerts']
    assert transform(fixed['code'], 0)['status'] == 'incompatible'
    assert not validate(real['code'], fixed['code'] + '\nraise RuntimeError()')['security_verified']
    assert validate(real['code'], 'def broken(')['regression']


def test_official_negative_cases_unchanged():
    for row in load_split('train'):
        if not row['vulnerable']:
            assert transform(row['code'], 0)['code'] == row['code']


def test_controlled_sql_binding():
    # Only trusted, fixed harness queries execute; never code extracted from input.
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE USERS (username TEXT, password TEXT)')
        db.executemany('INSERT INTO USERS VALUES (?, ?)', [('alice','secret'),('bob',"a'b")])
        assert db.execute(QUERY, ('secret',)).fetchall() == [('alice',)]
        assert db.execute(QUERY, ("a'b",)).fetchall() == [('bob',)]
        assert db.execute(QUERY, ("' OR 1=1 --",)).fetchall() == []


def test_env_contract_no_label_leak(real):
    env = SecureCodeEnv([real])
    check_env(env, skip_render_check=True)
    other = SecureCodeEnv([{**real, 'id':'different', 'vulnerable':False}])
    assert env.reset(seed=42)[0] == other.reset(seed=42)[0]
    state, reward, term, trunc, info = env.step(0)
    assert reward == -1 and not term and not trunc
    _, reward, *_ = env.step(3)
    assert reward == 9
    _, reward, *_ = env.step(3)
    assert reward == -6  # No repeated validation reward exploitation.
    assert env.step(4)[2]
    with pytest.raises(RuntimeError):
        env.step(4)


def test_stop_and_budget_penalties(real):
    env = SecureCodeEnv([real], max_steps=1)
    env.reset()
    assert env.step(4)[1] == -9
    env.reset()
    _, reward, terminated, truncated, _ = env.step(0)
    assert reward == -9 and truncated and not terminated


def test_bellman_terminal_and_checkpoint(tmp_path):
    agent = QLearningAgent(3, alpha=.1, gamma=.95)
    agent.q[1, 0] = 10
    agent.update(0, 0, 2, 1, False)
    assert agent.q[0,0] == pytest.approx(1.15)
    agent.update(2, 0, 2, 1, True)
    assert agent.q[2,0] == pytest.approx(.2)
    agent.save(tmp_path / 'q.npz', {'seed':42})
    loaded, _ = QLearningAgent.load(tmp_path / 'q.npz')
    assert np.array_equal(agent.q, loaded.q)
    assert loaded.act(0, deterministic=True) == 0


def test_untrusted_text_not_executed(tmp_path):
    target = tmp_path / 'executed'
    code = f'open({str(target)!r}, "w").write("bad")\nexec(user_input)'
    assert analyze(code)['alerts'][0]['cwe'] == 94
    assert bandit_scan(code)['status'] == 'completed'
    transform(code, 2)
    assert not target.exists()


def test_reject_different_sql_and_shell(real):
    code = real['code'].replace('SELECT username from USERS', 'DELETE from USERS')
    assert transform(code, 0)['status'] == 'incompatible'
    assert transform(real['code'], 1)['status'] == 'unsupported'
    assert transform(real['code'], 2)['status'] == 'unsupported'
