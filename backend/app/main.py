import json
from functools import lru_cache

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.app.agents.qlearning import QLearningAgent
from backend.app.analysis.static import analyze, bandit_scan
from backend.app.datasets.core import ROOT
from backend.app.environment.securecode import SecureCodeEnv, Rewards, STATE_SCHEMA
from backend.app.transformations.general import repair_remaining

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
    # A pending (unvalidated) policy edit is discarded; only validated text moves forward.
    policy_code = env.before_pending if env.pending else env.code if env.security_verified else body.code
    actions = [dict(t, source='Q-Learning') for t in env.trace]
    # The tabular policy only knows the OWASP Benchmark shapes; general rules handle the rest.
    final, extra, unfixed, general = repair_remaining(policy_code)
    actions += extra
    remaining = analyze(final)['alerts']
    fixed = env.security_verified or bool(general)
    if final == body.code:
        status = 'unsupported'
    elif fixed and not remaining and not unfixed:
        status = 'validated'
    elif fixed:
        status = 'partial'
    else:
        status = 'unverified'
    return dict(original=body.code, modified=final, changed=final != body.code, status=status,
                validation=env.validation or (general[-1] if general else None),
                general_validations=general, unfixed=unfixed,
                actions=actions, seed=meta['seed'], alerts=remaining,
                notice='Validação AST restrita às expressões alteradas (o restante do código é idêntico). '
                       'Cookies Secure exigem HTTPS. Equivalência funcional não verificada; revisão humana necessária.')


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


@app.get('/api/v1/model/supervised')
def supervised_metrics():
    """Out-of-fold file classification results: linear families, baselines and the post-hoc MLP run."""
    linear = read_json('artifacts/supervised/evaluation.json')
    rows = [dict(r, seed=linear['seed']) for r in linear['summary']]
    folds = [{k: v for k, v in f.items() if k != 'predictions'} for f in linear['folds'] if 'selection' in f]
    mlp = None
    try:
        mlp = json.loads((ROOT / 'artifacts/supervised/mlp.json').read_text())
    except FileNotFoundError:
        pass
    if mlp:
        rows += mlp['summary']
        folds += [{k: v for k, v in f.items() if k != 'predictions'} for f in mlp['folds']]
        mlp = {k: mlp[k] for k in ('seeds', 'grid', 'note', 'post_hoc', 'across_seeds')}
    return dict(examples=sum(rows[0]['metrics']['confusion'].values()), folds=4, seed=linear['seed'],
                summary=rows, fold_selection=folds, mlp=mlp)


@app.get('/api/v1/experiments')
def experiments():
    return [{k:v for k,v in e.items() if k != 'episodes'} for e in read_json('artifacts/metrics/test.json')['experiments']]


@app.get('/api/v1/experiments/{experiment_id}')
def experiment(experiment_id: str):
    for e in read_json('artifacts/metrics/test.json')['experiments']:
        if e['id'] == experiment_id:
            return e
    raise HTTPException(404, 'Experimento não encontrado.')
