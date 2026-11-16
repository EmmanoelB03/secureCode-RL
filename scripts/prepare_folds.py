"""Freeze balanced group folds using labels only for stratification."""
import collections
import random
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.app.datasets.core import ROOT, load_split, write_json, digest
from backend.app.transformations.registry import applicable


def make_folds(rows, k=4, seed=42):
    groups = collections.defaultdict(list)
    for r in rows:
        groups[r['group']].append(r)
    strata = lambda r: (r['cwe'],r['vulnerable'],bool(applicable(r['code'])))
    counts = {g:collections.Counter(strata(r) for r in rs) for g,rs in groups.items()}
    total = collections.Counter(strata(r) for r in rows)
    rng = random.Random(seed)
    best = None
    for _ in range(10000):
        assigned = {g:rng.randrange(k) for g in sorted(groups)}
        fold_counts = [collections.Counter() for _ in range(k)]
        for g,f in assigned.items():
            fold_counts[f].update(counts[g])
        score = sum((c[s]-total[s]/k)**2/total[s] for c in fold_counts for s in total)
        score += 1000 * sum(c[s]==0 for c in fold_counts for s in total if s[1] and s[2])
        if best is None or score < best[0]:
            best = score,assigned
    partitions = [[r for r in rows if best[1][r['group']]==i] for i in range(k)]
    folds = []
    for i in range(k):
        parts = dict(test=partitions[i], validation=partitions[(i+1)%k],
                     train=sum([p for j,p in enumerate(partitions) if j not in (i,(i+1)%k)], []))
        if not all(parts.values()):
            raise ValueError('Empty partition')
        folds.append(dict(fold=i, **{name:dict(ids=sorted(r['id'] for r in rs),
            groups=sorted({r['group'] for r in rs}), count=len(rs),
            distribution=dict(collections.Counter(f"CWE-{r['cwe']}/{r['official_label']}" for r in rs)),
            treatable=sum(bool(applicable(r['code'])) and r['vulnerable'] for r in rs)) for name,rs in parts.items()}))
    return dict(protocol='exploratory_group_cv_v2', k=k, seed=seed,
        independent_confirmation=False, config_selection='Fixed hyperparameters; inner validation reported, no test tuning',
        rationale='Four folds: SQL positives span only four flow groups.', folds=folds)


if __name__=='__main__':
    report=make_folds(load_split('all'))
    report['dataset_sha256']=digest((ROOT/'datasets/processed/all.json').read_bytes())
    write_json(ROOT/'datasets/manifests/folds.json',report)
    print([(f['fold'],{s:(f[s]['count'],f[s]['treatable']) for s in ('train','validation','test')}) for f in report['folds']])
