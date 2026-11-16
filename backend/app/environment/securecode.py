from dataclasses import asdict, dataclass

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from backend.app.analysis.static import analyze
from backend.app.transformations.registry import transform, applicable, FIX_ACTIONS, CWES
from backend.app.validation.checks import validate

ACTIONS = {0: 'FIX_SQL_INJECTION', 1: 'FIX_COMMAND_INJECTION', 2: 'FIX_CODE_INJECTION', 3: 'VALIDATE', 4: 'STOP', 5: 'FIX_SECURE_COOKIE', 6: 'FIX_RANDOM_BYTES'}
STATE_SCHEMA = 2


@dataclass(frozen=True)
class Rewards:
    validated: float = 10
    complete: float = 15
    functional: float = 3
    incompatible: float = -5
    regression: float = -12
    unnecessary: float = -6
    unfinished: float = -8
    cost: float = -1


class SecureCodeEnv(gym.Env):
    metadata = {'render_modes': []}

    def __init__(self, records, max_steps=6, rewards=None):
        if not records or max_steps < 1:
            raise ValueError('Nonempty records and positive max_steps required')
        self.records, self.max_steps = records, max_steps
        self.rewards = rewards or Rewards()
        self.dims = (32, 4, 5, max_steps + 1, 2, 4, 8)
        self.observation_space = spaces.Discrete(int(np.prod(self.dims)))
        self.action_space = spaces.Discrete(len(ACTIONS))
        self.done = True

    def features(self):
        result = analyze(self.code)
        mask = sum(1 << i for i, cwe in enumerate(CWES) if any(a['cwe'] == cwe for a in result['alerts']))
        return (mask, min(len(result['alerts']), 3), self.last, self.max_steps - self.steps,
                int(self.pending), self.status, sum(1 << i for i,a in enumerate(FIX_ACTIONS) if a in applicable(self.code)))

    def observation(self):
        return int(np.ravel_multi_index(self.features(), self.dims))

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        index = (options or {}).get('index')
        if index is None:
            index = int(self.np_random.integers(len(self.records)))
        self.record = self.records[index]
        self.original = self.code = self.record['code']
        self.steps = self.last = 0
        self.status = 0 if analyze(self.code)['syntax_valid'] else 3
        self.pending = self.changed = self.security_verified = False
        self.functional_verified = False
        self.validation = None
        self.pending_action = None
        self.validated_changes = 0
        self.done = False
        self.trace = []
        return self.observation(), {}

    def step(self, action):
        if self.done:
            raise RuntimeError('reset() required after termination')
        if not self.action_space.contains(action):
            raise ValueError('Invalid action')
        self.steps += 1
        reward = self.rewards.cost
        outcome = 'stopped'
        terminated = action == 4
        if action in (0,1,2,5,6):
            result = transform(self.code, action)
            outcome = result['status']
            if result['status'] == 'proposed' and not self.pending:
                self.before_pending = self.code
                self.pending_action = action
                self.code, self.pending, self.changed = result['code'], True, True
                self.security_verified = False
                self.last, self.status = 1, 0
                if self.record.get('vulnerable') is False:
                    reward += self.rewards.unnecessary
            else:
                self.last = 2
                reward += self.rewards.incompatible
        elif action == 3:
            if not self.pending:
                self.last = 2
                outcome = 'incompatible'
                reward += self.rewards.incompatible
            else:
                self.validation = validate(self.before_pending, self.code, self.pending_action)
                outcome = self.validation['status']
                self.pending = False
                self.security_verified = self.validation['security_verified']
                self.functional_verified = self.validation['functional_verified']
                if self.security_verified:
                    self.validated_changes += self.validation['changes']
                    self.last, self.status = 3, 1
                    reward += self.rewards.validated
                    if self.functional_verified:
                        reward += self.rewards.functional
                        if not applicable(self.code):
                            reward += self.rewards.complete
                elif self.validation['regression']:
                    self.last, self.status = 4, 3
                    reward += self.rewards.regression
                    self.code = self.before_pending
                else:
                    self.last, self.status = 4, 2
        truncated = self.steps >= self.max_steps and not terminated
        if (terminated or truncated) and (self.pending or applicable(self.code)):
            reward += self.rewards.unfinished
        self.done = terminated or truncated
        entry = dict(action=ACTIONS[int(action)], outcome=outcome, reward=reward)
        self.trace.append(entry)
        return self.observation(), float(reward), terminated, truncated, entry.copy()
