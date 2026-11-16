import numpy as np
from backend.app.transformations.registry import FIX_ACTIONS


class RandomAgent:
    def __init__(self, seed):
        self.rng = np.random.default_rng(seed)

    def act(self, state, deterministic=True):
        return int(self.rng.integers(7))


class RuleBasedAgent:
    def __init__(self, dims):
        self.dims = dims

    def act(self, state, deterministic=True):
        mask, count, last, remaining, pending, status, applicable = np.unravel_index(state, self.dims)
        if pending:
            return 3
        if applicable:
            return next(a for i,a in enumerate(FIX_ACTIONS) if applicable & (1 << i))
        return 4
