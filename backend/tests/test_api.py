from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.datasets.core import load_split

client = TestClient(app)


def test_health_and_input_validation():
    assert client.get('/api/v1/health').json()['executes_submitted_code'] is False
    assert client.post('/api/v1/analyze', json={'code':''}).status_code == 422
    assert client.post('/api/v1/analyze', json={'code':'x'*50001}).status_code == 422
    assert client.post('/api/v1/analyze', json={'code':'def broken('}).json()['syntax_valid'] is False


def test_dataset_and_trained_api():
    assert client.get('/api/v1/dataset/info').json()['total'] == 1230
    assert client.get('/api/v1/dataset/distribution').json()['89']['transformable'] == 5
    assert client.get('/api/v1/model/info').status_code == 200
    code = next(r['code'] for r in load_split('validation') if r['cwe']==89 and r['vulnerable'])
    response = client.post('/api/v1/repair', json={'code':code})
    assert response.status_code == 200
    assert response.json()['status'] == 'validated'
    assert response.json()['validation']['functional_verified'] is False
    assert client.get('/api/v1/experiments/unknown').status_code == 404
    experiments = client.get('/api/v1/experiments').json()
    assert len(experiments) == 9
    assert client.get('/api/v1/experiments/'+experiments[0]['id']).status_code == 200
    metrics=client.get('/api/v1/model/metrics')
    assert metrics.status_code == 200
    cv=metrics.json()['cross_validation']
    assert cv['examples']==454 and len(cv['folds'])==4
    assert len(cv['experiments'])==36
    for cwe in (614,330):
        from backend.app.transformations.registry import applicable
        code=next(r['code'] for r in load_split('all') if r['cwe']==cwe and applicable(r['code']))
        fixed=client.post('/api/v1/repair',json={'code':code})
        assert fixed.status_code==200 and fixed.json()['status']=='validated'
