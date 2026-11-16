"""Load only the locally generated classifier artifact; never accept uploaded models."""
import json
from functools import lru_cache
import joblib
import sklearn
from backend.app.datasets.core import ROOT, digest
from training.supervised import cleaned_source

@lru_cache(maxsize=1)
def load_model():
    folder=ROOT/'artifacts/supervised'
    meta=json.loads((folder/'model.json').read_text())
    if meta['sklearn']!=sklearn.__version__ or meta['preprocessing_sha256']!=digest((ROOT/'training/supervised.py').read_bytes()):
        raise ValueError('Modelo incompatível; execute training/fit_supervised.py')
    if meta['model_sha256']!=digest((folder/'model.joblib').read_bytes()):
        raise ValueError('Integridade do modelo inválida')
    return joblib.load(folder/'model.joblib'),meta

def classify(code):
    model,meta=load_model()
    text,_=cleaned_source(code)
    if not text.strip():
        return dict(status='unsupported',label='Entrada sem tokens de código',version=meta['version'])
    positive=bool(model.predict([text])[0])
    return dict(status='completed',positive=positive,
        label='Possível vulnerabilidade' if positive else 'Não identificada pelo modelo',
        version=meta['version'],model=meta['selected']['kind'],
        notice='Classificação experimental do arquivo; não localiza falhas nem comprova segurança. Sem validação externa.')
