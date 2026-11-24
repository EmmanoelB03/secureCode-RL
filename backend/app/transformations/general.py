"""General-purpose repairs for code outside the OWASP Benchmark shapes.

Used by the API only *after* the Q-Learning policy: the RL environment, its
metrics and checkpoints keep using the restricted transformations in
``registry.py``/``sql.py``. Every edit here is an expression-level rewrite
with byte-exact splicing (comments and formatting are preserved), plus an
optional ``import`` line. ``validate_general`` independently rebuilds the
expected AST and confirms nothing else changed. Submitted code is never run.
"""
import ast
import copy
import re
from functools import lru_cache

from backend.app.analysis.static import analyze

ACTION_CWE = {0: 89, 1: 78, 2: 94, 5: 614, 6: 330}
ACTION_NAMES = {0: 'FIX_SQL_INJECTION', 1: 'FIX_COMMAND_INJECTION', 2: 'FIX_CODE_INJECTION',
                5: 'FIX_SECURE_COOKIE', 6: 'FIX_RANDOM_BYTES'}
SCOPES = {
    0: 'Consulta SQL parametrizada (placeholders ? ou %s); valores passam separados do SQL.',
    1: 'Comando executado como lista de argumentos, sem shell; o valor externo vira um único argumento.',
    2: 'eval() trocado por ast.literal_eval(): aceita apenas literais Python (números, strings, listas, dicts...).',
    5: 'Cookie com secure=True (só trafega via HTTPS).',
    6: 'Gerador do módulo random trocado por random.SystemRandom() (aleatoriedade do sistema operacional).',
}
PERCENT_DRIVERS = {'psycopg2', 'psycopg', 'pymysql', 'MySQLdb', 'mysql', 'mysql.connector', 'pgdb'}
SHELL_SPECIAL = set('|&;<>()$`\\*?[]#~!{}\n')
RANDOM_FUNCS = {'random', 'randint', 'getrandbits', 'randbytes', 'normalvariate', 'randrange',
                'choice', 'choices', 'uniform', 'sample', 'shuffle'}
COMMAND_SINKS = {'os.system', 'os.popen', 'subprocess.run', 'subprocess.call', 'subprocess.Popen',
                 'subprocess.check_output', 'subprocess.check_call'}


class Unsupported(Exception):
    """Pattern recognised but no semantics-preserving rewrite is known."""


def _key(node):
    return (type(node).__name__, node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def _imports(tree):
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names |= {a.asname or a.name for a in n.names}
            names |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module:
            names.add(n.module)
    return names


def _rebinds(tree, name):
    """True if `name` is assigned/defined anywhere other than a plain `import name`."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store):
            return True
        if isinstance(n, ast.arg) and n.arg == name:
            return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name:
            return True
        if isinstance(n, ast.ImportFrom) and any((a.asname or a.name) == name for a in n.names):
            return True
        if isinstance(n, ast.Import) and any(a.asname == name for a in n.names):
            return True
    return False


# --------------------------------------------------------------------------- templates
def _template(node):
    """Split a string-building expression into literal text and expression slots.

    Returns a list of ``str`` or ``(expr_node, needs_str)``; ``needs_str`` is True
    when the original code converted the value with str() implicitly.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(v.value)
            elif v.conversion == -1 and v.format_spec is None:
                parts.append((v.value, True))
            else:  # keep formatting exactly: wrap the slot as its own f-string
                parts.append((ast.JoinedStr(values=[v]), False))
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # String concatenation: any operand that is not itself a template is a value slot.
        left = _template(node.left) or [(node.left, False)]
        right = _template(node.right) or [(node.right, False)]
        if not any(isinstance(p, str) for p in left + right):
            return None  # e.g. a + b with no literal text: could be numeric addition
        return left + right
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) \
            and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
        values = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        if isinstance(node.right, ast.Dict) or any(isinstance(v, ast.Starred) for v in values):
            return None
        text, parts, i, k = node.left.value, [], 0, 0
        buf = ''
        while i < len(text):
            if text[i] == '%':
                spec = text[i + 1:i + 2]
                if spec == '%':
                    buf += '%'
                    i += 2
                    continue
                if spec not in ('s', 'd', 'i') or k >= len(values):
                    return None
                parts += [buf, (values[k], True)]
                buf, i, k = '', i + 2, k + 1
            else:
                buf += text[i]
                i += 1
        if k != len(values):
            return None
        return parts + [buf]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format' \
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) \
            and not node.keywords and not any(isinstance(a, ast.Starred) for a in node.args):
        text, parts, buf, k, i = node.func.value.value, [], '', 0, 0
        while i < len(text):
            if text.startswith('{{', i) or text.startswith('}}', i):
                buf += text[i]
                i += 2
            elif text[i] == '{':
                end = text.find('}', i)
                field = text[i + 1:end]
                if end < 0:
                    return None
                if field == '':
                    idx, k = k, k + 1
                elif field.isdigit():
                    idx = int(field)
                else:
                    return None
                if idx >= len(node.args):
                    return None
                parts += [buf, (node.args[idx], True)]
                buf, i = '', end + 1
            else:
                buf += text[i]
                i += 1
        return parts + [buf]
    return None


def _has_slots(parts):
    return parts is not None and any(isinstance(p, tuple) for p in parts)


def _fstring(pieces):
    """Source of an f-string equivalent to concatenating text and slots."""
    values = []
    for p in pieces:
        if isinstance(p, str):
            if p:
                values.append(ast.Constant(value=p))
        elif isinstance(p[0], ast.JoinedStr):
            values.extend(p[0].values)
        else:
            values.append(ast.FormattedValue(value=p[0], conversion=-1, format_spec=None))
    return ast.unparse(ast.JoinedStr(values=values))


def _value_source(pieces, raw=False):
    if len(pieces) == 1 and not isinstance(pieces[0], str):
        node, needs_str = pieces[0]
        if raw and isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'str' \
                and len(node.args) == 1 and not node.keywords:
            node = node.args[0]  # drivers bind native values; str() was only needed to concatenate
        src = ast.unparse(node)
        return f'str({src})' if needs_str and not raw and not isinstance(node, ast.JoinedStr) else src
    return _fstring(pieces)


# --------------------------------------------------------------------------- SQL (CWE-89)
def _parameterize(parts, style):
    """Return (query, [param_sources]) or raise Unsupported."""
    query, params = '', []
    quote, inside = None, []
    for p in parts:
        if isinstance(p, str):
            for ch in p:
                if quote:
                    if ch == quote:
                        if any(not isinstance(x, str) for x in inside):
                            if quote == '"':
                                raise Unsupported('Valor externo dentro de identificador entre aspas duplas.')
                            query += '?' if style == '?' else '%s'
                            params.append(_value_source(_merge(inside), raw=True))
                        else:
                            text = ''.join(inside)
                            query += quote + (text.replace('%', '%%') if style == '%s' else text) + quote
                        quote, inside = None, []
                    else:
                        inside.append(ch)
                elif ch in ("'", '"'):
                    quote = ch
                else:
                    query += '%%' if (ch == '%' and style == '%s') else ch
        elif quote:
            inside.append(p)
        else:
            if not _value_position(query):
                raise Unsupported('Valor externo usado como nome de tabela/coluna ou trecho de SQL; exige lista de permissões manual.')
            query += '?' if style == '?' else '%s'
            params.append(_value_source([p], raw=True))
    if quote:
        raise Unsupported('Aspas não balanceadas na consulta SQL.')
    if not params:
        raise Unsupported('Consulta sem valores externos.')
    return query, params


VALUE_AFTER = ('=', '<', '>', ' LIKE', ' LIMIT', ' OFFSET', ' BETWEEN', ' IS', ' THEN', ' ELSE')


def _value_position(query):
    """An unquoted slot is a bindable value only right after a comparison/value keyword."""
    before = ' ' + re.sub(r'\s+', ' ', query).rstrip().upper()
    if before.endswith(VALUE_AFTER) or re.search(r' BETWEEN (\?|%S) AND$', before):
        return True
    if before.endswith(('(', ',')):  # only inside VALUES (...) or IN (...)
        depth, k = 0, len(before) - 1
        while k >= 0:
            if before[k] == ')':
                depth += 1
            elif before[k] == '(':
                if depth == 0:
                    return before[:k].rstrip().endswith((' VALUES', ' IN'))
                depth -= 1
            k -= 1
    return False


def _merge(chars):
    merged = []
    for x in chars:
        if isinstance(x, str) and merged and isinstance(merged[-1], str):
            merged[-1] += x
        else:
            merged.append(x)
    return merged


def _blocks(tree):
    """Yield (call, block, index): each call once, with the statement list that directly holds it."""
    for owner in ast.walk(tree):
        for field in ('body', 'orelse', 'finalbody'):
            block = getattr(owner, field, None)
            if not isinstance(block, list) or not block or not isinstance(block[0], ast.stmt):
                continue
            for i, stmt in enumerate(block):
                stack = [stmt]
                while stack:
                    node = stack.pop()
                    if isinstance(node, ast.Call):
                        yield node, block, i
                    stack.extend(c for c in ast.iter_child_nodes(node)
                                 if not isinstance(c, (ast.stmt, ast.excepthandler, ast.match_case)))


def _resolve(name, block, i):
    """Latest `name = ...` before block[i], if `name` is read exactly once afterwards (in block[i])."""
    for j in range(i - 1, -1, -1):
        prev = block[j]
        if isinstance(prev, ast.Assign) and len(prev.targets) == 1 \
                and isinstance(prev.targets[0], ast.Name) and prev.targets[0].id == name:
            later = block[j + 1:]
            reads = sum(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
                        for s in later for n in ast.walk(s))
            writes = any(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store)
                         for s in block[j + 1:i + 1] for n in ast.walk(s))
            return (prev, j) if reads == 1 and not writes else (None, j)
    return None, None


def _tuple(items):
    return f"({items[0]},)" if len(items) == 1 else f"({', '.join(items)})"


def _sql_edits(tree, notes):
    style = '%s' if _imports(tree) & PERCENT_DRIVERS else '?'
    found = []
    for call, block, i in _blocks(tree):
        if not (isinstance(call.func, ast.Attribute) and call.func.attr in ('execute', 'executemany')
                and len(call.args) == 1 and not call.keywords):
            continue
        arg, assign = call.args[0], None
        if isinstance(arg, ast.Name):  # query built in a variable earlier in the same block
            assign, j = _resolve(arg.id, block, i)
            if assign is None:
                if j is not None and _has_slots(_template(block[j].value)):
                    notes.append(dict(cwe=89, line=call.lineno,
                                      reason='Variável da consulta é reutilizada/alterada; parametrize manualmente.'))
                continue
            source = assign.value
        else:
            source = arg
        parts = _template(source)
        if not _has_slots(parts):
            continue
        try:
            query, params = _parameterize(parts, style)
        except Unsupported as exc:
            notes.append(dict(cwe=89, line=call.lineno, reason=str(exc)))
            continue
        if assign is not None:
            # Params are now evaluated at execute(): refuse if any of their names changes in between.
            used = {n.id for s in params for n in ast.walk(ast.parse(s, mode='eval')) if isinstance(n, ast.Name)}
            changed = {n.id for s in block[j + 1:i] for n in ast.walk(s)
                       if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            if used & changed:
                notes.append(dict(cwe=89, line=call.lineno, reason='Valores da consulta mudam antes do execute().'))
                continue
            found.append(('replace', assign.value, repr(query)))
            found.append(('add_arg', call, _tuple(params)))
        else:
            found.append(('replace', arg, repr(query)))
            found.append(('add_arg', call, _tuple(params)))
    return found, set()


# --------------------------------------------------------------------------- command (CWE-78)
def _argv(parts):
    """Shell-like tokenization without a shell: returns list of element sources."""
    tokens, current, quote, started = [], [], None, False
    for p in parts:
        if not isinstance(p, str):
            current.append(p)
            started = True
            continue
        for ch in p:
            if quote:
                if ch == quote:
                    quote = None
                elif quote == '"' and ch in '$`\\':
                    raise Unsupported('Expansão de shell dentro de aspas duplas.')
                else:
                    current.append(ch)
            elif ch in ("'", '"'):
                quote, started = ch, True
            elif ch in ' \t':
                if started:
                    tokens.append(_merge(current))
                current, started = [], False
            elif ch in SHELL_SPECIAL:
                raise Unsupported(f'Comando usa recurso do shell ({ch!r}: pipe, redirecionamento, variável...); revisão manual.')
            else:
                current.append(ch)
                started = True
    if quote:
        raise Unsupported('Aspas não balanceadas no comando.')
    if started:
        tokens.append(_merge(current))
    if not tokens or len(tokens[0]) != 1 or not isinstance(tokens[0][0], str):
        raise Unsupported('O nome do programa vem de entrada externa; exige lista de permissões manual.')
    return [repr(t[0]) if len(t) == 1 and isinstance(t[0], str) else
            (repr('') if not t else _value_source(t)) for t in tokens]


def _command_edits(tree, notes):
    found, need = [], set()
    if _rebinds(tree, 'subprocess'):
        return found, need
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for call, block, i in _blocks(tree):
        name = ast.unparse(call.func)
        if name not in COMMAND_SINKS or not call.args:
            continue
        arg = call.args[0]
        if isinstance(arg, (ast.List, ast.Tuple)):
            continue
        shell_kw = next((k for k in call.keywords if k.arg == 'shell'), None)
        if name.startswith('subprocess.') and not (shell_kw and isinstance(shell_kw.value, ast.Constant)
                                                   and shell_kw.value.value is True):
            continue
        target, assign = arg, None
        if isinstance(arg, ast.Name):
            assign, _ = _resolve(arg.id, block, i)
            target = assign.value if assign is not None else None
        parts = _template(target) if target is not None else None
        if parts is None:
            notes.append(dict(cwe=78, line=call.lineno,
                              reason='Comando montado fora deste trecho; não dá para separar os argumentos com segurança.'))
            continue
        try:
            argv = '[' + ', '.join(_argv(parts)) + ']'
        except Unsupported as exc:
            notes.append(dict(cwe=78, line=call.lineno, reason=str(exc)))
            continue
        if assign is not None:
            found.append(('replace', assign.value, argv))
            lst = arg.id
        else:
            lst = argv
        if name == 'os.system':
            if len(call.args) != 1 or call.keywords:
                continue
            used = not isinstance(parents.get(call), ast.Expr)
            found.append(('replace', call, f'subprocess.run({lst}){".returncode" if used else ""}'))
            need.add('subprocess')
        elif name == 'os.popen':
            outer = parents.get(parents.get(call))
            if not (isinstance(parents.get(call), ast.Attribute) and parents[call].attr == 'read'
                    and isinstance(outer, ast.Call) and not outer.args and len(call.args) == 1):
                if assign is not None:
                    found.pop()
                notes.append(dict(cwe=78, line=call.lineno, reason='os.popen() sem .read() direto não é reescrito.'))
                continue
            found.append(('replace', outer, f'subprocess.run({lst}, capture_output=True, text=True).stdout'))
            need.add('subprocess')
        else:
            if assign is None:
                found.append(('replace', arg, lst))
            found.append(('replace', shell_kw.value, 'False'))
    return found, need


# --------------------------------------------------------------------------- eval (CWE-94)
def _code_edits(tree, notes):
    found, need = [], set()
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        name = ast.unparse(call.func)
        if name in ('eval', 'builtins.eval'):
            if len(call.args) == 1 and not call.keywords and not _rebinds(tree, 'eval') and not _rebinds(tree, 'ast'):
                found.append(('replace', call.func, 'ast.literal_eval'))
                need.add('ast')
            else:
                notes.append(dict(cwe=94, line=call.lineno, reason='eval() com globals/locals executa código de propósito; revisão manual.'))
        elif name in ('exec', 'builtins.exec'):
            notes.append(dict(cwe=94, line=call.lineno,
                              reason='exec() executa código arbitrário: não existe troca automática segura. Remova o exec ou use um despacho por dicionário/lista de permissões.'))
    return found, need


# --------------------------------------------------------------------------- cookie (CWE-614)
def _cookie_edits(tree, notes):
    found = []
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'set_cookie'):
            continue
        secure = next((k for k in call.keywords if k.arg == 'secure'), None)
        if secure is not None:
            if isinstance(secure.value, ast.Constant) and secure.value.value is False:
                found.append(('replace', secure.value, 'True'))
            continue
        if any(k.arg is None for k in call.keywords) or any(isinstance(a, ast.Starred) for a in call.args):
            continue
        if len(call.args) >= 8:  # Flask/Werkzeug: positional secure is the 8th parameter
            continue
        if call.args or call.keywords:
            found.append(('add_kw', call, 'secure=True'))
    return found, set()


# --------------------------------------------------------------------------- random (CWE-330)
def _random_edits(tree, notes):
    found = []
    if 'random' not in _imports(tree) or _rebinds(tree, 'random'):
        return found, set()
    if any(isinstance(n, ast.Call) and ast.unparse(n.func) == 'random.seed' for n in ast.walk(tree)):
        notes.append(dict(cwe=330, line=1, reason='random.seed() indica reprodutibilidade intencional; SystemRandom ignora seed. Revise manualmente.'))
        return found, set()
    for call in ast.walk(tree):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) \
                and isinstance(call.func.value, ast.Name) and call.func.value.id == 'random' \
                and call.func.attr in RANDOM_FUNCS:
            found.append(('replace', call.func, f'random.SystemRandom().{call.func.attr}'))
    return found, set()


EDITORS = {0: _sql_edits, 1: _command_edits, 2: _code_edits, 5: _cookie_edits, 6: _random_edits}


# --------------------------------------------------------------------------- splicing
def _import_line(tree, code):
    """1-based line after which new imports go (0 = start of file)."""
    body = tree.body
    last = None
    for n in body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            last = n
        elif last is not None or not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)):
            break
    if last is not None:
        return last.end_lineno, body.index(last) + 1
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[0].end_lineno, 1
    lines = code.splitlines()
    k = 0
    while k < len(lines) and lines[k].startswith('#'):
        k += 1
    return k, 0


def _missing(tree, need):
    have = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names if a.asname is None}
    return sorted(m for m in need if m not in have and not _rebinds(tree, m))


@lru_cache(maxsize=1024)
def general_transform(code, action):
    if action not in EDITORS:
        return dict(status='unsupported', code=code, changes=0, notes=[], reason='Ação sem transformação.')
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return dict(status='incompatible', code=code, changes=0, notes=[], reason='Sintaxe incompatível.')
    notes = []
    edits, need = EDITORS[action](tree, notes)
    if not edits:
        return dict(status='incompatible', code=code, changes=0, notes=notes, reason='Nenhum padrão corrigível.')
    data = code.encode()
    offsets = [0]
    for line in data.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    pos = lambda line, col: offsets[line - 1] + col
    spans = []
    for kind, node, text in edits:
        if kind == 'replace':
            spans.append((pos(node.lineno, node.col_offset), pos(node.end_lineno, node.end_col_offset), text))
        else:  # add_arg / add_kw: insert after the last argument
            last = max(list(node.args) + [k.value for k in node.keywords], key=lambda n: (n.end_lineno, n.end_col_offset))
            at = pos(last.end_lineno, last.end_col_offset)
            spans.append((at, at, ', ' + text))
    spans.sort(reverse=True)
    for (s, e, _), (s2, e2, _) in zip(spans[1:], spans):
        if e > s2:  # overlapping edits would corrupt text
            return dict(status='incompatible', code=code, changes=0, notes=notes, reason='Edições sobrepostas.')
    for s, e, text in spans:
        data = data[:s] + text.encode() + data[e:]
    new = data.decode()
    imports = _missing(tree, need)
    if imports:
        line, _ = _import_line(tree, code)
        lines = new.splitlines(keepends=True)
        if line and line <= len(lines) and not lines[line - 1].endswith('\n'):
            lines[line - 1] += '\n'
        lines[line:line] = [f'import {m}\n' for m in imports]
        new = ''.join(lines)
    return dict(status='proposed', code=new, changes=len({id(n) for _, n, _ in edits}), notes=notes,
                imports=imports, reason=SCOPES[action])


@lru_cache(maxsize=1024)
def validate_general(original, modified, action):
    """Independent check: expected AST (original + intended edits) must equal the result,
    and the CWE sinks targeted must no longer be reported by the static analyzer."""
    result = dict(status='unverified', security_verified=False, functional_verified=False,
                  regression=None, scope=SCOPES.get(action, 'unsupported'), changes=0)
    try:
        before, after = ast.parse(original), ast.parse(modified)
    except (SyntaxError, ValueError, RecursionError):
        return {**result, 'status': 'regression', 'regression': True}
    edits, need = EDITORS[action](before, [])
    if not edits or original == modified:
        return result
    expected = copy.deepcopy(before)
    plan = {}
    for kind, node, text in edits:
        plan[_key(node)] = (kind, text)

    class Apply(ast.NodeTransformer):
        def visit(self, node):
            if hasattr(node, 'lineno') and _key(node) in plan:
                kind, text = plan[_key(node)]
                node = self.generic_visit(node)
                if kind == 'replace':
                    return ast.parse(text, mode='eval').body
                extra = ast.parse(f'f({text})', mode='eval').body
                if kind == 'add_arg':
                    node.args.extend(extra.args)
                else:
                    node.keywords.extend(extra.keywords)
                return node
            return super().visit(node)

    expected = Apply().visit(expected)
    imports = _missing(before, need)
    _, index = _import_line(before, original)
    expected.body[index:index] = [ast.Import(names=[ast.alias(name=m)]) for m in imports]
    if ast.dump(expected, include_attributes=False) != ast.dump(after, include_attributes=False):
        return result
    cwe = ACTION_CWE[action]
    left = sum(a['cwe'] == cwe for a in analyze(modified)['alerts'])
    if left >= max(1, sum(a['cwe'] == cwe for a in analyze(original)['alerts'])) and action not in (5,):
        return result
    return {**result, 'status': 'validated', 'security_verified': True, 'changes': len(plan)}


def repair_remaining(code, max_rounds=3):
    """Apply every general repair still applicable; returns (code, trace, notes, validations)."""
    trace, notes, validations = [], [], []
    for _ in range(max_rounds):
        progressed = False
        for action in (0, 1, 2, 5, 6):
            proposal = general_transform(code, action)
            if proposal['status'] != 'proposed':
                continue
            check = validate_general(code, proposal['code'], action)
            trace.append(dict(action=ACTION_NAMES[action], outcome='proposed', reward=None, source='regras gerais',
                              detail=proposal['reason']))
            trace.append(dict(action='VALIDATE', outcome=check['status'], reward=None, source='regras gerais'))
            if check['security_verified']:
                code, progressed = proposal['code'], True
                validations.append({**check, 'action': ACTION_NAMES[action]})
        if not progressed:
            break
    for action in (0, 1, 2, 5, 6):
        for n in general_transform(code, action)['notes']:
            if n not in notes:
                notes.append(n)
    return code, trace, notes, validations
