import ast
import copy
from functools import lru_cache

from backend.app.transformations.sql import QUERY, candidates


@lru_cache(maxsize=2048)
def validate(original, modified):
    """Independent AST comparison: only approved execute arguments may change.

    Certifies a local SQL binding property, never whole-program equivalence.
    """
    result = dict(status='unverified', security_verified=False, functional_verified=False,
                  regression=None, scope='SQLite parameter binding only', changes=0)
    try:
        before, after = ast.parse(original), ast.parse(modified)
    except (SyntaxError, ValueError, RecursionError):
        return {**result, 'status': 'regression', 'regression': True}
    targets = candidates(before)
    if not targets or original == modified:
        return result
    expected = copy.deepcopy(before)
    for call, variable in candidates(expected):
        call.args = [ast.Constant(value=QUERY), ast.Tuple(elts=[ast.Name(id=variable, ctx=ast.Load())], ctx=ast.Load())]
    if ast.dump(expected, include_attributes=False) != ast.dump(after, include_attributes=False):
        return result
    # Property is syntactic: all new execute calls bind one value, never interpolate it.
    return {**result, 'status': 'validated', 'security_verified': True, 'changes': len(targets)}
