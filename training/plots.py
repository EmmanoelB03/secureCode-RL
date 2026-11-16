import json
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('MPLCONFIGDIR', '/tmp/securecode-matplotlib')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

from backend.app.datasets.core import ROOT, write_json


def main():
    output = ROOT / 'artifacts/plots'
    output.mkdir(parents=True, exist_ok=True)
    training = json.loads((ROOT / 'artifacts/metrics/training.json').read_text())
    test = json.loads((ROOT / 'artifacts/metrics/test.json').read_text())
    curves = {}
    for metric, name in [('reward','reward'), ('epsilon','epsilon'), ('validated','correction')]:
        fig, ax = plt.subplots(figsize=(8,4))
        for run in training['runs']:
            seed = run['seed']
            history = pd.read_csv(ROOT / f'artifacts/metrics/history-{seed}.csv')
            smooth = history[metric].rolling(100, min_periods=1).mean()
            ax.plot(history.episode, smooth, label=f'Seed {seed}')
            if name == 'reward':
                curves[str(seed)] = history.assign(reward=smooth, validated=history.validated.rolling(100,min_periods=1).mean()).iloc[::100].to_dict('records')
        ax.set(xlabel='Episode (rolling window 100)', ylabel=metric)
        ax.legend()
        fig.tight_layout()
        fig.savefig(output / f'{name}.png', dpi=160)
        plt.close(fig)
    write_json(ROOT / 'artifacts/metrics/curves.json', curves)
    rows = pd.DataFrame([dict(policy=e['policy'], seed=e['seed'], reward=e['metrics']['mean_reward']) for e in test['experiments']])
    fig, ax = plt.subplots(figsize=(8,4))
    summary = rows.groupby('policy').reward.agg(['mean','std'])
    ax.bar(summary.index, summary['mean'], yerr=summary['std'].fillna(0), capsize=4)
    ax.set(ylabel='Mean reward ± SD across seeds', title='Identical held-out cases')
    fig.tight_layout(); fig.savefig(output / 'agents.png', dpi=160); plt.close(fig)
    category = pd.DataFrame([dict(policy=e['policy'], cwe=c, rate=m['validated_correction_rate']) for e in test['experiments'] for c,m in e['by_cwe'].items()])
    ax = category.groupby(['cwe','policy']).rate.mean().unstack().plot.bar(figsize=(8,4), ylim=(0,1))
    ax.set(ylabel='Validated local corrections / official positives')
    plt.tight_layout(); plt.savefig(output / 'categories.png', dpi=160); plt.close()
    actions = pd.DataFrame([dict(policy=e['policy'], **e['metrics']['actions']) for e in test['experiments']]).fillna(0)
    actions.groupby('policy').mean().plot.bar(stacked=True, figsize=(10,5))
    plt.ylabel('Mean action count per seed'); plt.tight_layout()
    plt.savefig(output / 'actions.png', dpi=160); plt.close()
    cv = json.loads((ROOT / 'artifacts/metrics/cross_validation.json').read_text())
    rows = pd.DataFrame([dict(policy=e['policy'], seed=e['seed'], fold=e['fold'],
        reward=e['metrics']['mean_reward'], correction=e['metrics']['treatable_correction_rate']) for e in cv['experiments']])
    for metric in ('reward','correction'):
        ax=rows.groupby(['fold','policy'])[metric].mean().unstack().plot.bar(figsize=(9,4))
        ax.set(ylabel=metric, title='Grouped CV: held-out fold, mean across seeds')
        plt.tight_layout(); plt.savefig(output/f'cv_{metric}.png',dpi=160); plt.close()
    rows=pd.DataFrame([dict(policy=e['policy'],cwe=c,rate=m['treatable_correction_rate']) for e in cv['pooled'] for c,m in e['by_cwe'].items() if m['treatable']])
    rows.groupby(['cwe','policy']).rate.mean().unstack().plot.bar(figsize=(9,4),ylim=(0,1))
    plt.ylabel('Validated / treatable, out-of-fold'); plt.tight_layout()
    plt.savefig(output/'cv_categories.png',dpi=160); plt.close()


if __name__ == '__main__':
    main()
