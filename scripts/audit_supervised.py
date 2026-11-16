"""Audit label clues and duplicate groups without executing OWASP examples."""
import ast
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.datasets.core import ROOT, digest, load_split, write_json


class StripDocs(ast.NodeTransformer):
    def _body(self, node):
        body = getattr(node, 'body', None)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body.pop(0)
        return self.generic_visit(node)
    visit_Module = _body
    visit_FunctionDef = _body
    visit_AsyncFunctionDef = _body
    visit_ClassDef = _body


def clean(code):
    tree = ast.parse(code)
    tree = StripDocs().visit(tree)
    return ast.unparse(tree)


def main():
    rows = load_split('all')
    source = ROOT / 'datasets/raw/BenchmarkPython/testcode'
    exact, normalized, comments, docstrings, names = collections.defaultdict(list), collections.defaultdict(list), collections.Counter(), collections.Counter(), collections.Counter()
    syntax_errors = []
    snippets = []
    for row in rows:
        code = row['code']
        exact[digest(code.encode())].append(row['id'])
        comments[row['vulnerable']] += sum(1 for line in code.splitlines() if line.lstrip().startswith('#'))
        try:
            tree = ast.parse(code)
            docstrings[row['vulnerable']] += sum(1 for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and ast.get_docstring(n))
            normalized[ digest(clean(code).encode()) ].append(row['id'])
            all_names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
            names[row['vulnerable']] += len(all_names)
        except SyntaxError as exc:
            syntax_errors.append({'id':row['id'],'line':exc.lineno,'message':exc.msg})
        official = (source / f"{row['id']}.py").read_text()
        if official != code: raise ValueError(f"Source mismatch: {row['id']}")
        if len(snippets)<3:
            snippets.append({'id':row['id'],'cwe':row['cwe'],'vulnerable':row['vulnerable'],'raw':code[:800],'cleaned':clean(code)[:800] if row['id'] not in {x['id'] for x in syntax_errors} else None})
    group_overlap = collections.defaultdict(list)
    folds = json.loads((ROOT/'datasets/manifests/folds.json').read_text())['folds']
    for f in folds:
        for split in ('train','validation','test'):
            for g in f[split]['groups']: group_overlap[f"{f['fold']}:{g}"].append(split)
        for g, parts in list(group_overlap.items()):
            if g.startswith(f"{f['fold']}:") and len(parts)>1: raise ValueError(f"group leakage {g}: {parts}")
    report={'dataset_sha256':digest((ROOT/'datasets/processed/all.json').read_bytes()),'examples':len(rows),'labels':dict(collections.Counter(str(r['vulnerable']) for r in rows)),'cwes':dict(collections.Counter(str(r['cwe']) for r in rows)),'syntax_errors':syntax_errors,'comment_lines_by_label':dict(comments),'docstrings_by_label':dict(docstrings),'ast_name_count_by_label':dict(names),'exact_duplicate_groups':[v for v in exact.values() if len(v)>1],'docstring_stripped_duplicate_groups':[v for v in normalized.values() if len(v)>1],'flow_groups':len(set(r['group'] for r in rows)),'fold_groups_verified':len(folds),'examples':len(rows),'illustrations':snippets}
    write_json(ROOT/'datasets/manifests/supervised/audit.json',report)
    print(json.dumps({k:v for k,v in report.items() if k!='illustrations'},indent=2))

if __name__=='__main__': main()
