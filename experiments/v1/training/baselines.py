import numpy as np


class RandomAgent:
    def __init__(self, seed):
        self.rng = np.random.default_rng(seed)

    def act(self, state, deterministic=True):
        return int(self.rng.integers(5))


class RuleBasedAgent:
    def __init__(self, dims):
        self.dims = dims

    def act(self, state, deterministic=True):
        mask, count, last, remaining, pending, status, applicable = np.unravel_index(state, self.dims)
        if pending:
            return 3
        if applicable:
            return 0
        return 4
