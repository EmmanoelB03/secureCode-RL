import json
from functools import lru_cache

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.app.agents.qlearning import QLearningAgent
from backend.app.analysis.static import analyze, bandit_scan
from backend.app.datasets.core import ROOT
from backend.app.environment.securecode import SecureCodeEnv, Rewards, STATE_SCHEMA

app = FastAPI(title='SecureCode RL', version='0.1.0')


class CodeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=50000)


def read_json(relative):
    try:
        return json.loads((ROOT / relative).read_text())
    except FileNotFoundError:
        raise HTTPException(503, 'Artefato indisponível. Execute preparação/treinamento/avaliação.')


@lru_cache(maxsize=1)
def policy():
    training = read_json('artifacts/metrics/training.json')
    try:
        return QLearningAgent.load(ROOT / f"artifacts/checkpoints/q-seed-{training['selected_seed']}.npz")
    except (OSError, ValueError, KeyError):
        raise HTTPException(503, 'Política treinada indisponível ou inválida.')


@app.get('/api/v1/health')
def health():
    return {'status': 'ok', 'executes_submitted_code': False}


@app.get('/api/v1/dataset/info')
def dataset_info():
    return read_json('datasets/manifests/dataset.json')


@app.get('/api/v1/dataset/distribution')
def distribution():
    return read_json('datasets/manifests/coverage.json')


@app.post('/api/v1/analyze')
def analyze_code(body: CodeRequest):
    from backend.app.analysis.classifier import classify
    try:
        classification = classify(body.code)
    except (OSError, ValueError, KeyError, ImportError) as exc:
        classification = {'status': 'unavailable', 'label': 'Classificador indisponível', 'notice': str(exc)}
    return {**analyze(body.code), 'classification': classification, 'bandit': bandit_scan(body.code),
            'notice': 'Ausência de alertas não comprova que o código está seguro.'}


@app.post('/api/v1/repair')
def repair(body: CodeRequest):
    agent, meta = policy()
    env = SecureCodeEnv([{'code':body.code}], meta['config']['max_steps'], Rewards(**meta['config']['rewards']))
    if env.observation_space.n != agent.q.shape[0] or meta.get('state_schema') != STATE_SCHEMA:
        raise HTTPException(503, 'Política incompatível com o ambiente.')
    state, _ = env.reset(seed=meta['seed'])
    while not env.done:
        state, *_ = env.step(agent.act(state, deterministic=True))
    status = 'validated' if env.security_verified else ('proposed' if env.pending else 'unverified' if env.changed else 'unsupported')
    return dict(original=body.code, modified=env.code, status=status, validation=env.validation,
                actions=env.trace, seed=meta['seed'], alerts=analyze(env.code)['alerts'],
                notice='Validação restrita à propriedade local modificada. Cookies Secure exigem HTTPS. Equivalência funcional não verificada; revisão humana necessária.')


@app.get('/api/v1/model/info')
def model_info():
    _, meta = policy()
    return meta


@app.get('/api/v1/model/metrics')
def metrics():
    return dict(training=read_json('artifacts/metrics/training.json'),
                evaluation=read_json('artifacts/metrics/test.json'),
                curves=read_json('artifacts/metrics/curves.json'),
                cross_validation=read_json('artifacts/metrics/cross_validation.json'))


@app.get('/api/v1/experiments')
def experiments():
    return [{k:v for k,v in e.items() if k != 'episodes'} for e in read_json('artifacts/metrics/test.json')['experiments']]


@app.get('/api/v1/experiments/{experiment_id}')
def experiment(experiment_id: str):
    for e in read_json('artifacts/metrics/test.json')['experiments']:
        if e['id'] == experiment_id:
            return e
    raise HTTPException(404, 'Experimento não encontrado.')
