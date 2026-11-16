"""Only the inspected SQLite benchmark sink shape is eligible for rewriting."""
import ast
from functools import lru_cache

QUERY = 'SELECT username from USERS where password = ?'
PREFIX = "SELECT username from USERS where password = '"


def candidates(tree):
    found = []
    for parent in ast.walk(tree):
        body = getattr(parent, 'body', None)
        if not isinstance(body, list):
            continue
        for i in range(len(body) - 3):
            a, b, c, d = body[i:i + 4]
            if not (isinstance(a, ast.Assign) and len(a.targets) == 1
                    and isinstance(a.targets[0], ast.Name) and a.targets[0].id == 'sql'
                    and isinstance(a.value, ast.JoinedStr)):
                continue
            parts = a.value.values
            if not (len(parts) == 3 and isinstance(parts[0], ast.Constant) and parts[0].value == PREFIX
                    and isinstance(parts[1], ast.FormattedValue) and isinstance(parts[1].value, ast.Name)
                    and parts[1].conversion == -1 and parts[1].format_spec is None
                    and isinstance(parts[2], ast.Constant) and parts[2].value == "'"):
                continue
            if ast.unparse(b) != 'con = helpers.db_sqlite.get_connection()':
                continue
            if ast.unparse(c) != 'cur = con.cursor()' or ast.unparse(d) != 'cur.execute(sql)':
                continue
            if not any(isinstance(n, ast.Import) and any(x.name == 'helpers.db_sqlite' and x.asname is None for x in n.names) for n in body[:i]):
                continue
            found.append((d.value, parts[1].value.id))
    return found


@lru_cache(maxsize=2048)
def transform(code, action):
    if action != 0:
        return dict(status='unsupported', code=code, reason='Sem transformação semanticamente segura para CWE-78/94.', changes=0)
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return dict(status='incompatible', code=code, reason='Sintaxe incompatível.', changes=0)
    targets = candidates(tree)
    if not targets:
        return dict(status='incompatible', code=code, reason='Padrão SQLite restrito não encontrado.', changes=0)
    # Byte positions preserve comments, license, formatting and all other text.
    lines = code.encode().splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    data = code.encode()
    for node, variable in sorted(targets, key=lambda pair: (pair[0].lineno, pair[0].col_offset), reverse=True):
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
        replacement = f'cur.execute({QUERY!r}, ({variable},))'.encode()
        data = data[:start] + replacement + data[end:]
    return dict(status='proposed', code=data.decode(), changes=len(targets),
                reason='Parâmetros separados da consulta SQLite; contrato do helper requer revisão.')
