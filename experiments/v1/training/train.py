import argparse
import json
import platform
import sys
from dataclasses import asdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import yaml

from backend.app.agents.qlearning import QLearningAgent
from backend.app.datasets.core import ROOT, load_split, write_json, digest
from backend.app.environment.securecode import SecureCodeEnv, Rewards
from training.evaluate import rollout, summarize


def train(config):
    records = load_split('train')
    validation = load_split('validation')
    manifest = json.loads((ROOT / 'datasets/manifests/dataset.json').read_text())
    summaries = []
    for seed in config['seeds']:
        env = SecureCodeEnv(records, config['max_steps'], Rewards(**config['rewards']))
        agent = QLearningAgent(env.observation_space.n, seed=seed, **{k:config[k] for k in ('alpha','gamma','epsilon','epsilon_min','epsilon_decay')})
        history = []
        for episode in range(config['episodes']):
            state, _ = env.reset(seed=seed if episode == 0 else None)
            total = 0
            while not env.done:
                action = agent.act(state)
                nxt, reward, terminated, truncated, _ = env.step(action)
                agent.update(state, action, reward, nxt, terminated or truncated)
                state = nxt
                total += reward
            history.append(dict(episode=episode+1, reward=total, epsilon=agent.epsilon,
                                validated=int(env.security_verified), steps=env.steps))
            agent.decay()
        metrics = summarize(rollout(agent, validation, config['max_steps'], env.rewards))
        metadata = dict(seed=seed, config=config, episodes=config['episodes'], dataset_commit=manifest['commit'],
                        manifest_sha256=digest((ROOT / 'datasets/manifests/dataset.json').read_bytes()),
                        validation=metrics, python=platform.python_version(), dimensions=list(env.dims),
                        state_schema=1, epsilon_final=agent.epsilon)
        agent.save(ROOT / f'artifacts/checkpoints/q-seed-{seed}.npz', metadata)
        pd.DataFrame(history).to_csv(ROOT / f'artifacts/metrics/history-{seed}.csv', index=False)
        summaries.append(metadata)
        print(f'Seed {seed}: {config["episodes"]} episódios; validação: {metrics["mean_reward"]:.3f}', flush=True)
    # Model chosen only using validation, deterministic lowest seed tie-break.
    selected = max(summaries, key=lambda m: (m['validation']['mean_reward'], -m['seed']))
    write_json(ROOT / 'artifacts/metrics/training.json', dict(runs=summaries, selected_seed=selected['seed']))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--config', type=Path, default=ROOT / 'training/config.yaml')
    args = p.parse_args()
    train(yaml.safe_load(args.config.read_text()))
