"""Outer grouped evaluation; each case is tested exactly once per seed.

The next group fold is reserved for validation. Hyperparameters are frozen;
neither test rewards nor pooled CV results select the deployed checkpoint.
"""
import json
import platform
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pandas as pd
import yaml
from backend.app.datasets.core import ROOT, load_split, write_json, digest
from backend.app.environment.securecode import STATE_SCHEMA
from backend.app.transformations.registry import CWES
from training.fit import fit
from training.baselines import RandomAgent, RuleBasedAgent
from training.evaluate import rollout, summarize, detection


def check_partitions(folds, records):
    ids={r['id'] for r in records}
    by_id={r['id']:r for r in records}
    tested=[]
    for f in folds:
        parts=[set(f[s]['ids']) for s in ('train','validation','test')]
        assert set.union(*parts)==ids
        for i in range(3):
            for j in range(i):
                assert not parts[i]&parts[j]
                assert not {by_id[x]['group'] for x in parts[i]} & {by_id[x]['group'] for x in parts[j]}
        tested.extend(f['test']['ids'])
    assert len(tested)==len(ids) and set(tested)==ids


def main():
    config=yaml.safe_load((ROOT/'training/config.yaml').read_text())
    manifest=json.loads((ROOT/'datasets/manifests/folds.json').read_text())
    if manifest['dataset_sha256']!=digest((ROOT/'datasets/processed/all.json').read_bytes()):
        raise ValueError('Stale folds; prepare folds again')
    records=load_split('all')
    check_partitions(manifest['folds'],records)
    by_id={r['id']:r for r in records}
    experiments=[]
    destination=ROOT/'artifacts/cross_validation'
    destination.mkdir(parents=True,exist_ok=True)
    for f in manifest['folds']:
        parts={s:[by_id[i] for i in f[s]['ids']] for s in ('train','validation','test')}
        for seed in config['seeds']:
            learned,history,env=fit(parts['train'],config,seed)
            val=summarize(rollout(learned,parts['validation'],config['max_steps'],env.rewards))
            metadata=dict(seed=seed,fold=f['fold'],config=config,state_schema=STATE_SCHEMA,
                python=platform.python_version(),dimensions=list(env.dims),validation=val,
                folds_sha256=digest((ROOT/'datasets/manifests/folds.json').read_bytes()),
                dataset_sha256=manifest['dataset_sha256'],training_ids=f['train']['ids'])
            learned.save(destination/f"q-fold-{f['fold']}-seed-{seed}.npz",metadata)
            pd.DataFrame(history).to_csv(destination/f"history-fold-{f['fold']}-seed-{seed}.csv",index=False)
            for name,agent in [('random',RandomAgent(seed+1000*f['fold'])),('rule_based',RuleBasedAgent(env.dims)),('q_learning',learned)]:
                rows=rollout(agent,parts['test'],config['max_steps'],env.rewards)
                experiments.append(dict(id=f"cv-{f['fold']}-{name}-{seed}",fold=f['fold'],seed=seed,policy=name,
                    metrics=summarize(rows),by_cwe={str(c):summarize([r for r in rows if r['cwe']==c]) for c in CWES},
                    validation=val if name=='q_learning' else None,episodes=rows))
            print(f"Fold {f['fold']} seed {seed} complete",flush=True)
    pooled=[]
    for seed in config['seeds']:
        for policy in ('random','rule_based','q_learning'):
            rows=sum([e['episodes'] for e in experiments if e['seed']==seed and e['policy']==policy],[])
            assert len({r['id'] for r in rows})==len(rows)==len(records)
            pooled.append(dict(seed=seed,policy=policy,metrics=summarize(rows),
                by_cwe={str(c):summarize([r for r in rows if r['cwe']==c]) for c in CWES}))
    report=dict(protocol=manifest['protocol'],independent_confirmation=False,folds=manifest['folds'],
                config=config,examples=len(records),groups=len({r['group'] for r in records}),
                detection=detection(records),pooled=pooled,experiments=experiments,
                caveat='Exploratory grouped CV after corpus inspection; seed SD is not a confidence interval; each case tested once per seed.')
    write_json(ROOT/'artifacts/metrics/cross_validation.json',report)
    pd.DataFrame([dict(seed=e['seed'],policy=e['policy'],**{k:v for k,v in e['metrics'].items() if k!='actions'}) for e in pooled]).to_csv(ROOT/'artifacts/metrics/cross_validation.csv',index=False)


if __name__=='__main__':
    main()
