import json
from pathlib import Path

import numpy as np


class QLearningAgent:
    def __init__(self, states, actions=5, alpha=.1, gamma=.95, epsilon=1.,
                 epsilon_min=.05, epsilon_decay=.995, seed=42):
        self.q = np.zeros((states, actions), dtype=np.float64)
        self.alpha, self.gamma = alpha, gamma
        self.epsilon, self.epsilon_min, self.epsilon_decay = epsilon, epsilon_min, epsilon_decay
        self.rng = np.random.default_rng(seed)
        self.seed = seed

    def act(self, state, deterministic=False):
        if not deterministic and self.rng.random() < self.epsilon:
            return int(self.rng.integers(self.q.shape[1]))
        values = self.q[state]
        tied = np.flatnonzero(values == values.max())
        # Deterministic tie-breaking is index order, independent of code and labels.
        return int(tied[0] if deterministic else self.rng.choice(tied))

    def update(self, state, action, reward, next_state, done):
        target = reward + (0 if done else self.gamma * self.q[next_state].max())
        self.q[state, action] += self.alpha * (target - self.q[state, action])

    def decay(self):
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

    def save(self, path, metadata):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(path, q=self.q, metadata=json.dumps(metadata))

    @classmethod
    def load(cls, path):
        with np.load(path, allow_pickle=False) as data:
            table = data['q']
            if table.ndim != 2 or table.shape[1] != 5 or not np.isfinite(table).all():
                raise ValueError('Invalid Q-table')
            metadata = json.loads(str(data['metadata']))
            agent = cls(table.shape[0], epsilon=0, seed=metadata['seed'])
            agent.q = table.copy()
        return agent, metadata
