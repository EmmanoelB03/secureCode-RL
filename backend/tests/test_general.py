import ast
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.app.analysis.static import analyze
from backend.app.datasets.core import ROOT
from backend.app.main import app
from backend.app.transformations.general import general_transform, validate_general, repair_remaining

EXAMPLES = ROOT / 'examples/vulneraveis'
client = TestClient(app)


def fix(code):
    return repair_remaining(code)


def test_sql_fstring_is_parameterized_and_binds_safely():
    code = ('import sqlite3\n'
            'def login(cur, u, p):\n'
            '    cur.execute(f"SELECT id FROM users WHERE username = \'{u}\' AND password = \'{p}\'")\n')
    new, _, notes, vals = fix(code)
    assert "cur.execute('SELECT id FROM users WHERE username = ? AND password = ?', (u, p))" in new
    assert vals and not notes and not analyze(new)['alerts']
    # Trusted harness: the rewritten query really neutralises the classic payload.
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE users (id INT, username TEXT, password TEXT)')
        db.execute("INSERT INTO users VALUES (1, 'alice', 's3cret')")
        query = 'SELECT id FROM users WHERE username = ? AND password = ?'
        assert db.execute(query, ('alice', "' OR '1'='1")).fetchall() == []
        assert db.execute(query, ('alice', 's3cret')).fetchall() == [(1,)]


def test_sql_variable_concat_like_and_percent_driver():
    code = ('import psycopg2\n'
            'def f(cur, termo):\n'
            '    q = "SELECT * FROM t WHERE nome LIKE \'%" + termo + "%\' AND x = 1"\n'
            '    cur.execute(q)\n')
    new, *_ = fix(code)
    assert "q = 'SELECT * FROM t WHERE nome LIKE %s AND x = 1'" in new
    assert "cur.execute(q, (f'%{termo}%',))" in new


def test_command_rewritten_without_shell():
    code = 'import os\ndef ping(h):\n    os.system(f"ping -c 1 {h}")\n'
    new, *_ = fix(code)
    assert "subprocess.run(['ping', '-c', '1', str(h)])" in new and 'import subprocess\n' in new
    assert not analyze(new)['alerts']


@pytest.mark.parametrize('code,reason', [
    ('import os\ndef f(a):\n    os.system(f"cat {a} | wc -l")\n', 'shell'),
    ('def f(c, t):\n    c.execute(f"SELECT * FROM {t}")\n', 'tabela'),
    ('def f(c):\n    exec(c)\n', 'exec'),
])
def test_abstains_with_reason(code, reason):
    new, trace, notes, _ = fix(code)
    assert new == code and not trace
    assert any(reason in n['reason'] for n in notes)


def test_eval_cookie_random():
    code = ('import random\nfrom flask import make_response\n'
            'def f(x):\n'
            '    v = eval(x)\n'
            '    r = make_response("ok")\n'
            '    r.set_cookie("a", "b")\n'
            '    r.set_cookie("c", "d", secure=False)\n'
            '    return random.randint(0, 9)\n')
    new, *_ = fix(code)
    assert 'ast.literal_eval(x)' in new and 'import ast\n' in new
    assert 'r.set_cookie("a", "b", secure=True)' in new and 'secure=False' not in new
    assert 'random.SystemRandom().randint(0, 9)' in new


def test_random_seed_is_left_alone():
    code = 'import random\nrandom.seed(1)\nx = random.random()\n'
    assert fix(code)[0] == code


def test_validation_rejects_extra_changes():
    code = 'import os\nos.system("ls " + d)\n'
    proposal = general_transform(code, 1)
    assert validate_general(code, proposal['code'], 1)['security_verified']
    assert not validate_general(code, proposal['code'] + 'x = 1\n', 1)['security_verified']
    assert validate_general(code, 'def broken(', 1)['regression']


def test_comments_and_formatting_preserved():
    code = '# header\nimport os  # keep\n\n\ndef f(d):\n    """doc"""\n    os.system("ls " + d)  # sink\n'
    new = fix(code)[0]
    assert new.startswith('# header\nimport os  # keep\nimport subprocess\n\n\ndef f(d):\n    """doc"""\n')
    assert new.endswith("subprocess.run(['ls', d])  # sink\n")


@pytest.mark.parametrize('path', sorted(EXAMPLES.glob('0[1-7]_*.py')), ids=lambda p: p.name)
def test_examples_are_actually_changed(path):
    code = path.read_text()
    body = client.post('/api/v1/repair', json={'code': code}).json()
    assert body['changed'] and body['modified'] != code
    assert body['status'] in ('validated', 'partial')
    ast.parse(body['modified'])
    assert len(analyze(body['modified'])['alerts']) < max(1, len(analyze(code)['alerts'])) \
        or 'secure=True' in body['modified']


def test_unfixable_example_reports_reasons():
    body = client.post('/api/v1/repair', json={'code': (EXAMPLES / '08_nao_corrigivel.py').read_text()}).json()
    assert body['status'] == 'unsupported' and body['changed'] is False
    assert {n['cwe'] for n in body['unfixed']} == {89, 78, 94}


@pytest.mark.parametrize('sql,ok', [
    ("f\"SELECT * FROM t WHERE {c} = '{v}'\"", False),
    ('f"SELECT {c} FROM t WHERE id = 1"', False),
    ('f"SELECT * FROM t ORDER BY {c}"', False),
    ('f"SELECT * FROM t WHERE id = {v} LIMIT {n}"', True),
    ('f"SELECT * FROM t WHERE id IN ({a}, {b})"', True),
    ('f"INSERT INTO t (nome, idade) VALUES ({a}, {b})"', True),
    ('f"INSERT INTO t ({a}) VALUES (1)"', False),
    ('f"SELECT * FROM t WHERE x BETWEEN {a} AND {b}"', True),
])
def test_unquoted_slots_only_in_value_positions(sql, ok):
    code = f'def f(c, a, b, v, n):\n    c.execute({sql})\n'
    assert (fix(code)[0] != code) is ok
