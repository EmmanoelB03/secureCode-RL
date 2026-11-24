"""Conservative sink detection, not a full interprocedural taint analyzer."""
import ast
import json
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=2048)
def analyze(code: str):
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return {'alerts': [], 'syntax_valid': False, 'error': str(exc)}
    alerts = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = ast.unparse(n.func)
        cwe = None
        if isinstance(n.func, ast.Attribute) and n.func.attr in {'execute', 'executemany', 'executescript'}:
            if n.args and len(n.args) < 2 and not isinstance(n.args[0], ast.Constant):
                cwe = 89
        elif name in {'exec', 'eval', 'builtins.exec', 'builtins.eval'}:
            cwe = 94
        elif name in {'os.system', 'os.popen'}:
            cwe = 78
        elif name in {'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_output', 'subprocess.check_call'}:
            # An argv list without shell=True is not interpreted by a shell.
            shell = any(k.arg == 'shell' and not (isinstance(k.value, ast.Constant) and k.value.value is False)
                        for k in n.keywords)
            explicit_no_shell = any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is False
                                    for k in n.keywords)
            if shell or not (explicit_no_shell or (n.args and isinstance(n.args[0], (ast.List, ast.Tuple)))):
                cwe = 78
        elif name.endswith('.set_cookie') and any(k.arg=='secure' and isinstance(k.value,ast.Constant) and k.value.value is False for k in n.keywords):
            cwe = 614
        elif name in {'random.random','random.randint','random.getrandbits','random.randbytes','random.normalvariate'}:
            cwe = 330
        if cwe:
            owasp = 'A05:2025 — Injection' if cwe in (89,78,94) else 'Categoria adicional; classificação por CWE'
            alerts.append(dict(cwe=cwe, line=n.lineno, sink=name, owasp=owasp,
                               status='detected', message='Possível vulnerabilidade; fluxo de dados não comprovado.'))
    return {'alerts': alerts, 'syntax_valid': True, 'error': None}


def bandit_scan(code):
    """Bandit parses text in a private temporary directory; never imports target."""
    with tempfile.TemporaryDirectory(prefix='securecode-') as folder:
        target = Path(folder) / 'input.py'
        target.write_text(code)
        try:
            proc = subprocess.run([sys.executable, '-m', 'bandit', '-q', '-f', 'json',
                                   '--ignore-nosec', str(target)], capture_output=True, text=True, timeout=15)
            if proc.returncode not in (0, 1):
                return {'status': 'unavailable', 'results': []}
            data = json.loads(proc.stdout)
            return {'status': 'completed', 'results': [
                {k: r[k] for k in ('test_id', 'issue_text', 'issue_severity', 'line_number', 'issue_cwe')}
                for r in data['results']], 'errors': data.get('errors', [])}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return {'status': 'unavailable', 'results': []}
