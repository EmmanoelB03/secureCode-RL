import argparse
import collections
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from backend.app.agents.qlearning import QLearningAgent
from backend.app.analysis.static import analyze
from backend.app.datasets.core import ROOT, load_split, write_json
from backend.app.environment.securecode import SecureCodeEnv, Rewards
from backend.app.transformations.sql import transform
from training.baselines import RandomAgent, RuleBasedAgent


def rollout(agent, records, max_steps=6, rewards=None):
    env = SecureCodeEnv(records, max_steps=max_steps, rewards=rewards)
    episodes = []
    for i, row in enumerate(records):
        state, _ = env.reset(options={'index': i})
        total = 0
        while not env.done:
            state, reward, _, _, _ = env.step(agent.act(state, deterministic=True))
            total += reward
        treatable = transform(row['code'], 0)['status'] == 'proposed'
        episodes.append(dict(id=row.get('id'), cwe=row.get('cwe'), vulnerable=row.get('vulnerable'),
            treatable=treatable, unsupported=bool(row.get('vulnerable') and not treatable),
            validated=env.security_verified, changed=env.changed,
            unnecessary=env.changed and row.get('vulnerable') is False,
            steps=env.steps, reward=total, pending=env.pending,
            functional_verified=env.functional_verified, trace=env.trace))
    return episodes


def summarize(rows):
    def ratio(n, d):
        return n / d if d else None
    positives = sum(r['vulnerable'] is True for r in rows)
    negatives = sum(r['vulnerable'] is False for r in rows)
    treatable = sum(r['treatable'] and r['vulnerable'] is True for r in rows)
    corrected = sum(r['validated'] and r['vulnerable'] is True for r in rows)
    return dict(examples=len(rows), positives=positives, negatives=negatives, treatable=treatable,
        validated=corrected, validated_correction_rate=ratio(corrected, positives),
        treatable_correction_rate=ratio(corrected, treatable),
        unnecessary_change_rate=ratio(sum(r['unnecessary'] for r in rows), negatives),
        functional_regression_rate=None, functional_verified_cases=0, full_success_rate=None,
        mean_actions=ratio(sum(r['steps'] for r in rows), len(rows)),
        mean_reward=ratio(sum(r['reward'] for r in rows), len(rows)),
        unsupported=sum(r['unsupported'] for r in rows),
        actions=dict(collections.Counter(t['action'] for r in rows for t in r['trace'])))


def detection(records):
    result = {}
    for cwe in (89, 78, 94):
        counts = collections.Counter()
        for r in records:
            if r['cwe'] != cwe:
                continue
            predicted = any(a['cwe'] == cwe for a in analyze(r['code'])['alerts'])
            counts[('t' if predicted == r['vulnerable'] else 'f') + ('p' if predicted else 'n')] += 1
        tp, fp, tn, fn = (counts[k] for k in ('tp', 'fp', 'tn', 'fn'))
        div = lambda n, d: n / d if d else None
        result[str(cwe)] = dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=div(tp, tp+fp),
            recall=div(tp,tp+fn), f1=div(2*tp,2*tp+fp+fn), fpr=div(fp,fp+tn), fnr=div(fn,fn+tp))
    return result


def evaluate(checkpoints, split='test'):
    records = load_split(split)
    experiments = []
    for checkpoint in checkpoints:
        learned, meta = QLearningAgent.load(checkpoint)
        steps = meta['config']['max_steps']
        rewards = Rewards(**meta['config']['rewards'])
        env = SecureCodeEnv(records, max_steps=steps, rewards=rewards)
        for name, agent in [('random', RandomAgent(meta['seed'])), ('rule_based', RuleBasedAgent(env.dims)), ('q_learning', learned)]:
            rows = rollout(agent, records, steps, rewards)
            experiments.append(dict(id=f"{split}-{name}-{meta['seed']}", policy=name, seed=meta['seed'],
                split=split, metrics=summarize(rows),
                by_cwe={str(c): summarize([r for r in rows if r['cwe'] == c]) for c in (89,78,94)}, episodes=rows))
    result = dict(split=split, detection=detection(records), experiments=experiments,
                  caveat='Local SQL property only; full functional validation unavailable. Tiny grouped holdout.')
    write_json(ROOT / f'artifacts/metrics/{split}.json', result)
    pd.DataFrame([dict(policy=e['policy'], seed=e['seed'], **{k:v for k,v in e['metrics'].items() if k != 'actions'}) for e in experiments]).to_csv(ROOT / f'artifacts/metrics/{split}.csv', index=False)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--split', choices=['validation', 'test'], default='test')
    args = p.parse_args()
    report = evaluate(sorted((ROOT / 'artifacts/checkpoints').glob('q-seed-*.npz')), args.split)
    print(json.dumps([{k:e[k] for k in ('id','metrics')} for e in report['experiments']], indent=2))
