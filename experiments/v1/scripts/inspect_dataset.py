import ast
import collections
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.datasets.core import ROOT, load_split, write_json
from backend.app.transformations.sql import transform


def inspect():
    coverage = {}
    rows = sum((load_split(s) for s in ('train', 'validation', 'test')), [])
    for cwe in (89, 78, 94):
        selected = [r for r in rows if r['cwe'] == cwe]
        usable = [r['id'] for r in selected if transform(r['code'], 0)['status'] == 'proposed'] if cwe == 89 else []
        invalid = []
        for r in selected:
            try:
                ast.parse(r['code'])
            except SyntaxError:
                invalid.append(r['id'])
        coverage[str(cwe)] = dict(total=len(selected), positive=sum(r['vulnerable'] for r in selected),
            negative=sum(not r['vulnerable'] for r in selected), transformable=len(usable),
            transformable_ids=usable, syntax_incompatible=invalid)
    write_json(ROOT / 'datasets/manifests/coverage.json', coverage)
    print(coverage)


if __name__ == '__main__':
    inspect()
