import ast
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
URL = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def flow_group(code):
    """Group generated flow templates, ignoring route/source/sink and literal values.

    Deliberately over-groups: same flow across CWEs remains in one partition.
    No claim of recovering the unavailable original generator templates.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return 'python-syntax-incompatible'
    post = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name.endswith('_post'))
    start = next((i for i, n in enumerate(post.body) if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'bar' for t in n.targets)), None)
    if start is None:
        return 'direct-flow'
    statements = []
    for node in post.body[start:]:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Try, ast.Return)):
            break
        statements.append(node)

    class Normalize(ast.NodeTransformer):
        def visit_Name(self, n):
            n.id = re.sub(r'\d+', '', n.id)
            return n

        def visit_Constant(self, n):
            return ast.copy_location(ast.Constant(value=type(n.value).__name__), n)

    normalized = Normalize().visit(ast.Module(body=statements, type_ignores=[]))
    return digest(ast.dump(normalized, include_attributes=False).encode())[:16]


def load_split(split):
    if split not in {'train', 'validation', 'test', 'all'}:
        raise ValueError('Invalid split')
    path = ROOT / 'datasets/processed' / f'{split}.json'
    rows = json.loads(path.read_text())
    for row in rows:
        if digest(row['code'].encode()) != row['sha256']:
            raise ValueError('Dataset content hash mismatch')
    return rows
