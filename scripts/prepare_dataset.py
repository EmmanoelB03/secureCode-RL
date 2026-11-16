"""Download/read the pinned official corpus without importing or executing it."""
import argparse
import collections
import csv
import json
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.datasets.core import ROOT, URL, COMMIT, digest, flow_group, write_json
from backend.app.transformations.registry import CWES


def prepare(repo, seed=42):
    if not repo.exists():
        subprocess.run(['git', 'clone', URL, str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), 'checkout', COMMIT], check=True)
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != COMMIT:
        raise ValueError(f'Expected pinned commit {COMMIT}, found {commit}')
    if subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Dataset repository must be clean')
    labels = repo / 'expectedresults-0.1.csv'
    records, counts = [], collections.Counter()
    seen = set()
    for row in csv.reader(line for line in labels.read_text().splitlines() if not line.startswith('#')):
        name, category, label, cwe = row
        if name in seen or label not in {'true', 'false'}:
            raise ValueError('Invalid labels')
        seen.add(name)
        source = repo / 'testcode' / f'{name}.py'
        code = source.read_text()
        counts[f'CWE-{cwe}/{label}'] += 1
        if int(cwe) in CWES:
            records.append(dict(id=name, category=category, vulnerable=label == 'true',
                                official_label=label, cwe=int(cwe), code=code,
                                source=f'testcode/{name}.py', sha256=digest(code.encode()),
                                commit=commit, group=flow_group(code)))
    groups = collections.defaultdict(list)
    for row in records:
        groups[row['group']].append(row)
    # Fixed randomized group assignment search minimizes size/category/label imbalance.
    # Labels used ONLY for stratification, never for observation or agent selection.
    strata = sorted({(r['cwe'], r['vulnerable']) for r in records})
    totals = collections.Counter((r['cwe'], r['vulnerable']) for r in records)
    rng, best = random.Random(seed), None
    for _ in range(5000):
        split = {k: [] for k in ('train', 'validation', 'test')}
        for group in sorted(groups):
            key = rng.choices(list(split), weights=[.7, .15, .15])[0]
            split[key].extend(groups[group])
        score = 0
        for key, proportion in zip(split, [.7, .15, .15]):
            c = collections.Counter((r['cwe'], r['vulnerable']) for r in split[key])
            score += sum((c[s] - proportion * totals[s]) ** 2 / totals[s] for s in strata)
            score += 100 * sum(c[s] == 0 for s in strata)
        if best is None or score < best[0]:
            best = score, split
    write_json(ROOT / 'datasets/processed/all.json', sorted(records,key=lambda r:r['id']))
    manifest = dict(dataset='OWASP Benchmark for Python', version='0.1', experiment_version=2, url=URL,
                    commit=commit, labels_sha256=digest(labels.read_bytes()), total=len(seen),
                    selected=len(records), distribution=dict(sorted(counts.items())), seed=seed,
                    grouping='Normalized flow AST across CWEs; heuristic, conservative, not original template IDs',
                    groups=len(groups), splits={})
    for key, rows in best[1].items():
        rows.sort(key=lambda r: r['id'])
        write_json(ROOT / f'datasets/processed/{key}.json', rows)
        manifest['splits'][key] = dict(count=len(rows), ids=[r['id'] for r in rows],
            groups=sorted({r['group'] for r in rows}),
            distribution=dict(collections.Counter(f"CWE-{r['cwe']}/{r['official_label']}" for r in rows)))
    write_json(ROOT / 'datasets/manifests/dataset.json', manifest)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=ROOT / 'datasets/raw/BenchmarkPython')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    prepare(args.repo, args.seed)
