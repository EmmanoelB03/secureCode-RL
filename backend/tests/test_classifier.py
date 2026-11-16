import pytest
from backend.app.analysis.classifier import classify, load_model
from training.supervised import cleaned_source
from backend.app.main import app
from fastapi.testclient import TestClient

def test_no_execution_and_normalization(tmp_path):
    marker=tmp_path/'executed'
    code=f'"""SECRET DOC"""\n# SECRET COMMENT\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\nx = eval(user_input)\n'
    cleaned,_=cleaned_source(code)
    assert 'SECRET' not in cleaned and 'eval' in cleaned
    assert classify(code)['status']=='completed'
    assert not marker.exists()

def test_api_classification_and_invalid_input():
    with TestClient(app) as client:
        response=client.post('/api/v1/analyze',json={'code':'x = eval(user_input)'})
        assert response.status_code==200
        assert response.json()['classification']['status']=='completed'
        assert client.post('/api/v1/analyze',json={'code':''}).status_code==422

def test_unavailable_model(monkeypatch):
    import backend.app.analysis.classifier as module
    def missing(): raise FileNotFoundError('Missing model')
    monkeypatch.setattr(module,'load_model',missing)
    with TestClient(app) as client:
        body=client.post('/api/v1/analyze',json={'code':'x = 1'}).json()
        assert body['classification']['status']=='unavailable'
        assert body['syntax_valid']
