import ast
import copy
from functools import lru_cache

from backend.app.transformations.sql import QUERY, candidates
from backend.app.transformations.registry import edits, SCOPES


@lru_cache(maxsize=2048)
def validate(original, modified, action=0):
    """Independent AST comparison: only approved execute arguments may change.

    Certifies a local SQL binding property, never whole-program equivalence.
    """
    result = dict(status='unverified', security_verified=False, functional_verified=False,
                  regression=None, scope=SCOPES.get(action, 'unsupported'), changes=0)
    try:
        before, after = ast.parse(original), ast.parse(modified)
    except (SyntaxError, ValueError, RecursionError):
        return {**result, 'status': 'regression', 'regression': True}
    targets = candidates(before) if action == 0 else edits(before, action)
    if not targets or original == modified:
        return result
    expected = copy.deepcopy(before)
    if action == 0:
        for call, variable in candidates(expected):
            call.args = [ast.Constant(value=QUERY), ast.Tuple(elts=[ast.Name(id=variable, ctx=ast.Load())], ctx=ast.Load())]
    else:
        replacements = {id(n): text for n,text in edits(expected, action)}
        class Replace(ast.NodeTransformer):
            def visit(self, node):
                if id(node) in replacements:
                    return ast.parse(replacements[id(node)], mode='eval').body
                return super().visit(node)
        expected = Replace().visit(expected)
        # Independent postcondition: the intended property must hold at each edited site.
        after_nodes = {}
        for n in ast.walk(after):
            if isinstance(n,(ast.Call,ast.Constant)):
                after_nodes.setdefault((n.lineno,n.col_offset), n)
        for node, _ in targets:
            new = after_nodes.get((node.lineno,node.col_offset))
            if action == 5 and not (isinstance(new,ast.Constant) and new.value is True):
                return result
            if action == 6 and not (isinstance(new,ast.Call) and ast.unparse(new)=='random.SystemRandom().randbytes(32)'):
                return result
    if ast.dump(expected, include_attributes=False) != ast.dump(after, include_attributes=False):
        return result
    # Property is syntactic: all new execute calls bind one value, never interpolate it.
    return {**result, 'status': 'validated', 'security_verified': True, 'changes': len(targets)}
