"""Exploratory comparison: TF-IDF + MLP under the same grouped protocol as training/supervised.py.

Reuses folds, normalization, metrics and the TF-IDF configuration of the linear experiment.
Writes artifacts/supervised/mlp.json; artifacts/supervised/evaluation.json is not modified.
The MLP was added after the linear results were known: this is a post-hoc, exploratory comparison.
"""
import argparse
import json
import platform
import statistics
import sys
import time
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline

from backend.app.datasets.core import ROOT, digest, load_split, write_json
from training.supervised import cleaned_source, groups_for_cv, metrics

# Reduced budget (short run): one seed, three configurations (linear families used six).
SEEDS = (42,)
GRID = [dict(hidden=(64,), alpha=a) for a in (1e-4, 1e-2, 1.0)]
OUTPUT = ROOT / 'artifacts/supervised/mlp.json'


def mlp_pipeline(hidden, alpha, seed):
    clf = MLPClassifier(hidden_layer_sizes=hidden, alpha=alpha, solver='adam', learning_rate_init=1e-3,
                        max_iter=200, random_state=seed)
    return Pipeline([('tfidf', TfidfVectorizer(token_pattern=r'(?u)\b\w+\b|[^\w\s]', ngram_range=(1, 2),
                                               max_features=50000, sublinear_tf=True)), ('clf', clf)])


def fit(model, texts, y):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always', ConvergenceWarning)
        model.fit(texts, y)
    return any(issubclass(w.category, ConvergenceWarning) for w in caught)


def main():
    rows = load_split('all')
    folds = groups_for_cv(rows)
    byid = {r['id']: r for r in rows}
    prep = {r['id']: cleaned_source(r['code'])[0] for r in rows}
    linear = json.loads((ROOT / 'artifacts/supervised/evaluation.json').read_text())
    manifest = ROOT / 'datasets/manifests/folds.json'
    assert linear['group_manifest_sha256'] == digest(manifest.read_bytes()), 'Folds differ from linear experiment'
    parser = argparse.ArgumentParser()
    parser.add_argument('--seeds', type=int, nargs='+', default=list(SEEDS))
    seeds = parser.parse_args().seeds
    grid = [dict(hidden_layer_sizes=list(g['hidden']), alpha=g['alpha']) for g in GRID]
    output = []
    if OUTPUT.exists():
        previous = json.loads(OUTPUT.read_text())
        if previous['grid'] == grid and previous['group_manifest_sha256'] == linear['group_manifest_sha256']:
            output = [f for f in previous['folds'] if f['seed'] not in seeds]
    for seed in seeds:
        for representation in ('raw', 'cleaned'):
            texts = {r['id']: (r['code'] if representation == 'raw' else prep[r['id']]) for r in rows}
            for fold in folds:
                train = [byid[i] for i in fold['train']['ids']]
                val = [byid[i] for i in fold['validation']['ids']]
                test = [byid[i] for i in fold['test']['ids']]
                y = lambda part: [int(r['vulnerable']) for r in part]
                best = None
                for cfg in GRID:
                    model = mlp_pipeline(cfg['hidden'], cfg['alpha'], seed)
                    fit(model, [texts[r['id']] for r in train], y(train))
                    score = f1_score(y(val), model.predict([texts[r['id']] for r in val]), average='macro', zero_division=0)
                    if best is None or score > best['score']:
                        best = dict(score=score, **cfg)
                chosen = mlp_pipeline(best['hidden'], best['alpha'], seed)
                start = time.perf_counter()
                not_converged = fit(chosen, [texts[r['id']] for r in train + val], y(train + val))
                fit_seconds = time.perf_counter() - start
                start = time.perf_counter()
                pred = [int(p) for p in chosen.predict([texts[r['id']] for r in test])]
                elapsed = time.perf_counter() - start
                output.append(dict(seed=seed, representation=representation, fold=fold['fold'], policy='mlp',
                                   selection={'validation_macro_f1': best['score'], 'hidden_layer_sizes': list(best['hidden']),
                                              'alpha': best['alpha']},
                                   converged=not not_converged, fit_seconds=fit_seconds,
                                   metrics=metrics(y(test), pred), inference_ms_per_file=1000 * elapsed / len(test),
                                   predictions=[dict(id=r['id'], cwe=r['cwe'], y=int(r['vulnerable']), pred=p, group=r['group'])
                                                for r, p in zip(test, pred)]))
                print(f"seed={seed} {representation} fold={fold['fold']} best={best} f1={output[-1]['metrics']['f1_positive']:.4f} fit={fit_seconds:.0f}s", flush=True)
        across = save(output, grid, manifest)
    print(json.dumps(across, indent=2))


def save(output, grid, manifest):
    done = sorted({f['seed'] for f in output})
    summary = []
    for seed in done:
        for rep in ('raw', 'cleaned'):
            es = [e for e in output if e['seed'] == seed and e['representation'] == rep]
            vals = sum([e['predictions'] for e in es], [])
            assert len(vals) == 454 and len({x['id'] for x in vals}) == 454
            bycwe = {str(c): metrics([x['y'] for x in vals if x['cwe'] == c], [x['pred'] for x in vals if x['cwe'] == c])
                     for c in sorted({x['cwe'] for x in vals})}
            summary.append(dict(seed=seed, representation=rep, policy='mlp',
                                metrics=metrics([x['y'] for x in vals], [x['pred'] for x in vals]), by_cwe=bycwe,
                                fold_f1=[e['metrics']['f1_positive'] for e in es],
                                mean_inference_ms_per_file=statistics.mean(e['inference_ms_per_file'] for e in es)))
    across = {}
    for rep in ('raw', 'cleaned'):
        f1s = [s['metrics']['f1_positive'] for s in summary if s['representation'] == rep]
        reps = [s for s in summary if s['representation'] == rep]
        mean = lambda key: statistics.mean(s['metrics'][key] for s in reps)
        std = lambda key: statistics.pstdev(s['metrics'][key] for s in reps)
        across[rep] = dict(f1_mean=statistics.mean(f1s), f1_std=statistics.pstdev(f1s), f1_by_seed=f1s,
                           seeds=[s['seed'] for s in reps],
                           metrics_mean={k: mean(k) for k in ('precision', 'recall', 'f1_positive', 'macro_f1', 'balanced_accuracy')},
                           metrics_std={k: std(k) for k in ('precision', 'recall', 'f1_positive', 'macro_f1', 'balanced_accuracy')},
                           fp_mean=statistics.mean(s['metrics']['confusion']['fp'] for s in reps),
                           fn_mean=statistics.mean(s['metrics']['confusion']['fn'] for s in reps))
    report = {'protocol': 'docs/supervised-protocol.md', 'exploratory': True, 'post_hoc': True,
              'note': 'MLP adicionado após os resultados lineares serem conhecidos; mesmos folds, limpeza e TF-IDF.',
              'seeds': done, 'grid': grid,
              'python': platform.python_version(), 'scikit_learn': __import__('sklearn').__version__,
              'group_manifest_sha256': digest(manifest.read_bytes()),
              'dataset_sha256': digest((ROOT / 'datasets/processed/all.json').read_bytes()),
              'script_sha256': digest(Path(__file__).read_bytes()),
              'folds': output, 'summary': summary, 'across_seeds': across}
    write_json(OUTPUT, report)
    return across


if __name__ == '__main__':
    main()
