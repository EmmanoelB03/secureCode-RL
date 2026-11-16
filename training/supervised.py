"""Grouped supervised classification experiment for the OWASP Python corpus."""
import ast
import collections
import hashlib
import io
import json
import platform
import random
import re
import statistics
import sys
import time
import tokenize
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from backend.app.analysis.static import analyze
from backend.app.datasets.core import ROOT, digest, load_split, write_json

SEED = 42


def cleaned_source(code):
    """Text-only normalization; tokenize also handles the corpus's newer f-strings."""
    code = re.sub(r'BenchmarkTest\d+', 'BenchmarkCase', code)
    code = re.sub(r'/benchmark/[a-zA-Z0-9_-]+/BenchmarkCase', '/benchmark/category/BenchmarkCase', code)
    # Generated flow variable/key suffixes are arbitrary case identifiers.
    code = re.sub(r'(?<=[A-Za-z_-])\d{4,}', 'ID', code)
    tokens = []
    previous = tokenize.INDENT
    try:
        for token in tokenize.generate_tokens(io.StringIO(code).readline):
            if token.type == tokenize.COMMENT:
                continue
            if token.type == tokenize.STRING and previous in (tokenize.INDENT, tokenize.NEWLINE):
                continue
            tokens.append((token.type, token.string))
            if token.type not in (tokenize.NL, tokenize.COMMENT, tokenize.ENCODING):
                previous = token.type
        return tokenize.untokenize(tokens), 'tokenized'
    except (tokenize.TokenError, IndentationError):
        raise ValueError('Cannot safely tokenize input; no raw fallback permitted')


def groups_for_cv(rows, k=4):
    folds = json.loads((ROOT/'datasets/manifests/folds.json').read_text())['folds']
    byid = {r['id']:r for r in rows}
    groups = collections.defaultdict(set)
    for f in folds:
        for split in ('train','validation','test'):
            for rid in f[split]['ids']:
                groups[byid[rid]['group']].add(split)
        for g in set(f['train']['groups']) & set(f['validation']['groups']) | set(f['train']['groups']) & set(f['test']['groups']) | set(f['validation']['groups']) & set(f['test']['groups']):
            raise ValueError(f"Original group crosses partitions in fold {f['fold']}: {g}")
    return folds


def metrics(y, pred):
    tn, fp, fn, tp = confusion_matrix(y,pred,labels=[0,1]).ravel()
    return {'examples':len(y),'precision':precision_score(y,pred,zero_division=0),
            'recall':recall_score(y,pred,zero_division=0),'f1_positive':f1_score(y,pred,zero_division=0),
            'macro_f1':f1_score(y,pred,average='macro',zero_division=0),
            'balanced_accuracy':balanced_accuracy_score(y,pred),'accuracy':accuracy_score(y,pred),
            'confusion':{'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp)}}


def pipeline(kind, c, class_weight):
    clf=LogisticRegression(C=c,class_weight=class_weight,max_iter=2000,random_state=SEED) if kind=='logistic' else LinearSVC(C=c,class_weight=class_weight,random_state=SEED)
    return Pipeline([('tfidf',TfidfVectorizer(token_pattern=r'(?u)\b\w+\b|[^\w\s]',ngram_range=(1,2),max_features=50000,sublinear_tf=True)),('clf',clf)])


def main():
    rows=load_split('all'); folds=groups_for_cv(rows)
    byid={r['id']:r for r in rows}; prep={}
    for r in rows: prep[r['id']]=cleaned_source(r['code'])
    for f in folds:
        sets=[{digest(prep[i][0].encode()) for i in f[part]['ids']} for part in ('train','validation','test')]
        assert all(not sets[i]&sets[j] for i in range(3) for j in range(i)), 'Normalized duplicates cross partitions'
    write_json(ROOT/'datasets/manifests/supervised/folds.json', {'folds':folds,'preprocessing_sha256':digest(Path(__file__).read_bytes())})
    output=[]
    for representation in ('raw','cleaned'):
      texts={r['id']:(r['code'] if representation=='raw' else prep[r['id']][0]) for r in rows}
      for fold in folds:
        train=[byid[i] for i in fold['train']['ids']]; val=[byid[i] for i in fold['validation']['ids']]; test=[byid[i] for i in fold['test']['ids']]
        ytrain=[int(r['vulnerable']) for r in train]
        majority=int(sum(ytrain)*2>=len(ytrain))
        for policy in ('majority','ast_rules'):
          pred=[majority for _ in test] if policy=='majority' else [int(bool(analyze(r['code'])['alerts'])) for r in test]
          output.append(dict(representation=representation,fold=fold['fold'],policy=policy,metrics=metrics([int(r['vulnerable']) for r in test],pred),predictions=[dict(id=r['id'],cwe=r['cwe'],y=int(r['vulnerable']),pred=p,group=r['group']) for r,p in zip(test,pred)]))
        for kind in ('logistic','linearsvc'):
          best=None
          for c in (.1,1.,10.):
           for weight in (None,'balanced'):
            model=pipeline(kind,c,weight)
            model.fit([texts[r['id']] for r in train],ytrain)
            vp=model.predict([texts[r['id']] for r in val])
            score=f1_score([int(r['vulnerable']) for r in val],vp,average='macro',zero_division=0)
            if best is None or score>best['score']:
             best=dict(score=score,kind=kind,c=c,class_weight=weight)
          chosen=pipeline(best['kind'],best['c'],best['class_weight'])
          chosen.fit([texts[r['id']] for r in train+val],[int(r['vulnerable']) for r in train+val])
          start=time.perf_counter()
          pred=chosen.predict([texts[r['id']] for r in test])
          elapsed=time.perf_counter()-start
          bycwe={str(cwe):metrics([int(r['vulnerable']) for r in test if r['cwe']==cwe],[int(p) for r,p in zip(test,pred) if r['cwe']==cwe]) for cwe in sorted({r['cwe'] for r in test})}
          output.append(dict(representation=representation,fold=fold['fold'],policy=best['kind'],selection={'validation_macro_f1':best['score'],'C':best['c'],'class_weight':best['class_weight']},metrics=metrics([int(r['vulnerable']) for r in test],[int(p) for p in pred]),by_cwe=bycwe,inference_seconds=elapsed,inference_ms_per_file=1000*elapsed/len(test),predictions=[dict(id=r['id'],cwe=r['cwe'],y=int(r['vulnerable']),pred=int(p),group=r['group']) for r,p in zip(test,pred)]))
    summary=[]
    for rep in ('raw','cleaned'):
      for policy in ('majority','ast_rules','logistic','linearsvc'):
        es=[e for e in output if e['representation']==rep and e['policy']==policy]
        vals=sum([e['predictions'] for e in es],[])
        assert len(vals)==454 and len({x['id'] for x in vals})==454
        m=metrics([x['y'] for x in vals],[x['pred'] for x in vals])
        bycwe={str(cwe):metrics([x['y'] for x in vals if x['cwe']==cwe],[x['pred'] for x in vals if x['cwe']==cwe]) for cwe in sorted({x['cwe'] for x in vals})}
        summary.append(dict(representation=rep,policy=policy,metrics=m,by_cwe=bycwe,fold_f1=[e['metrics']['f1_positive'] for e in es],mean_inference_ms_per_file=statistics.mean(e.get('inference_ms_per_file',0) for e in es)))
    report={'protocol':'docs/supervised-protocol.md','exploratory':True,'dataset_sha256':digest((ROOT/'datasets/processed/all.json').read_bytes()),'seed':SEED,'python':platform.python_version(),'scikit_learn':__import__('sklearn').__version__,'group_manifest_sha256':digest((ROOT/'datasets/manifests/folds.json').read_bytes()),'cleaning':{'method':'tokenization; comment/docstring removal; generated case/route/flow ID normalization','syntax_fallback_ids':[r['id'] for r in rows if prep[r['id']][1]=='raw_syntax_fallback'],'cleaned_sha256':{r['id']:digest(texts.encode()) for r in rows for texts in [prep[r['id']][0]]}},'folds':output,'summary':summary}
    write_json(ROOT/'artifacts/supervised/evaluation.json',report)
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
