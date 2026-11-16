"""Select deployment model using only the demonstrative training/validation split."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import joblib
import sklearn
from sklearn.metrics import f1_score
from training.supervised import pipeline, cleaned_source
from backend.app.datasets.core import ROOT, load_split, write_json, digest


def main():
    train, val = load_split('train'), load_split('validation')
    assert not {r['group'] for r in train}&{r['group'] for r in val}
    x=[cleaned_source(r['code'])[0] for r in train]
    xv=[cleaned_source(r['code'])[0] for r in val]
    assert not set(x)&set(xv)
    y=[r['vulnerable'] for r in train]; yv=[r['vulnerable'] for r in val]
    candidates=[]; best=None
    for kind in ('logistic','linearsvc'):
        for c in (.1,1.,10.):
            for weight in (None,'balanced'):
                model=pipeline(kind,c,weight).fit(x,y)
                score=float(f1_score(yv,model.predict(xv),average='macro'))
                candidate=dict(kind=kind,C=c,class_weight=weight,validation_macro_f1=score)
                candidates.append(candidate)
                if best is None or score>best[0]: best=(score,model,candidate)
    model=best[1].fit(x+xv,y+yv)
    dest=ROOT/'artifacts/supervised'; dest.mkdir(exist_ok=True,parents=True)
    joblib.dump(model,dest/'model.joblib')
    metadata=dict(version='supervised-1',sklearn=sklearn.__version__,selected=best[2],candidates=candidates,
        selection='demonstrative validation macro-F1 only; refit train+validation',
        training_ids=[r['id'] for r in train+val],test_used=False,
        preprocessing_sha256=digest((ROOT/'training/supervised.py').read_bytes()),
        model_sha256=digest((dest/'model.joblib').read_bytes()))
    write_json(dest/'model.json',metadata)
    print(best[2])
if __name__=='__main__':main()
