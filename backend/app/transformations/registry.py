"""V2 transformations. Labels and case IDs are never consulted."""
import ast
from functools import lru_cache

from backend.app.transformations.sql import transform as sql_transform

FIX_ACTIONS = (0, 5, 6)
CWES = (89, 78, 94, 614, 330)
SCOPES = {0: 'SQLite parameter binding', 5: 'Cookie Secure attribute (requires HTTPS)',
          6: 'OS-backed randomness for 32 bytes; token handling not certified'}


def edits(tree, action):
    """Return restricted expression replacements, preserving all surrounding text."""
    found = []
    for parent in ast.walk(tree):
        body = getattr(parent, 'body', None)
        if not isinstance(body, list):
            continue
        for i, statement in enumerate(body):
            if action == 5 and isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                call = statement.value
                if ast.unparse(call.func) != 'RESPONSE.set_cookie' or call.keywords is None:
                    continue
                # Require the inspected Flask response constructor immediately before.
                if i == 0 or ast.unparse(body[i-1]) != 'RESPONSE = make_response(RESPONSE)':
                    continue
                if not any(isinstance(n, ast.ImportFrom) and n.module == 'flask'
                           and any(a.name == 'make_response' and a.asname is None for a in n.names)
                           for n in body[:i]):
                    continue
                if any(k.arg is None for k in call.keywords):
                    continue
                for keyword in call.keywords:
                    if keyword.arg == 'secure' and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                        found.append((keyword.value, 'True'))
            elif action == 6:
                if not any(isinstance(n, ast.Import) and any(a.name == 'random' and a.asname is None for a in n.names) for n in body[:i]):
                    continue
                # Refuse rebinding of random in this scope, including parameters.
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(a.arg == 'random' for a in ast.walk(parent.args) if isinstance(a, ast.arg)):
                    continue
                if any(isinstance(n, ast.Name) and n.id == 'random' and isinstance(n.ctx, ast.Store) for s in body for n in ast.walk(s)):
                    continue
                # Only simple assignments; never rewrite arbitrary calls in other scopes.
                if not isinstance(statement, ast.Assign):
                    continue
                for call in ast.walk(statement.value):
                    if isinstance(call, ast.Call) and ast.unparse(call) == 'random.randbytes(32)':
                        found.append((call, 'random.SystemRandom().randbytes(32)'))
    return found


@lru_cache(maxsize=2048)
def transform(code, action):
    if action in (0, 1, 2):
        return sql_transform(code, action)
    if action not in FIX_ACTIONS:
        return dict(status='unsupported', code=code, changes=0, reason='Ação sem transformação.')
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return dict(status='incompatible', code=code, changes=0, reason='Sintaxe incompatível.')
    replacements = edits(tree, action)
    if not replacements:
        return dict(status='incompatible', code=code, changes=0, reason='Padrão restrito não encontrado.')
    offsets = [0]
    for line in code.encode().splitlines(keepends=True):
        offsets.append(offsets[-1]+len(line))
    data = code.encode()
    for node, replacement in sorted(replacements, key=lambda e: (e[0].lineno,e[0].col_offset), reverse=True):
        start = offsets[node.lineno-1]+node.col_offset
        end = offsets[node.end_lineno-1]+node.end_col_offset
        data = data[:start]+replacement.encode()+data[end:]
    return dict(status='proposed', code=data.decode(), changes=len(replacements), reason=SCOPES[action])


@lru_cache(maxsize=2048)
def applicable(code):
    return tuple(a for a in FIX_ACTIONS if transform(code,a)['status']=='proposed')
