"""Generate v2 results exclusively from recorded out-of-fold trajectories."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pandas as pd
from backend.app.datasets.core import ROOT


def main():
    cv=json.loads((ROOT/'artifacts/metrics/cross_validation.json').read_text())
    coverage=json.loads((ROOT/'datasets/manifests/coverage.json').read_text())
    data=pd.read_csv(ROOT/'artifacts/metrics/cross_validation.csv')
    report=['# Resultados v2 — validação cruzada por grupos','',
        'Protocolo: `docs/expansion.md`. Resultados e código v1 preservados em `experiments/v1/`.',
        f"Corpus oficial: {cv['examples']} casos, {cv['groups']} grupos de fluxo, {len(cv['folds'])} folds.",
        'Três sementes (42/43/44), 10.000 episódios por fold/semente, hiperparâmetros fixos.',
        'Cada caso é avaliado uma vez fora do treino por semente. Nenhum grupo atravessa',
        'treino, validação e teste da mesma rodada. A validação interna não inclui o teste.', '',
        '## Cobertura real', '',
        '| CWE | Casos | Positivos | Negativos | Transformáveis | Grupos transformáveis |',
        '|---|---:|---:|---:|---:|---:|']
    for c,m in coverage.items():
        report.append(f"| {c} | {m['total']} | {m['positive']} | {m['negative']} | {m['transformable']} | {m['transformable_groups']} |")
    report += ['',f"Total de candidatos: {sum(m['transformable'] for m in coverage.values())}, contra 5 na v1.",
        'Certificados locais: parametrização SQL, atributo Secure de cookie e fonte de',
        'aleatoriedade do SO para bytes. Cookies exigem HTTPS; nenhum certificado cobre',
        'equivalência funcional do programa inteiro ou o protocolo completo de autenticação.', '',
        '## Partições (total / tratáveis)', '',
        '| Fold | Treino | Validação | Teste |','|---|---:|---:|---:|']
    for f in cv['folds']:
        report.append(f"| {f['fold']+1} | "+' | '.join(f"{f[s]['count']} / {f[s]['treatable']}" for s in ('train','validation','test'))+' |')
    report += ['', '## Agregação fora do treino', '',
        'As métricas são calculadas concatenando trajetórias dos folds por semente, não',
        'fazendo média simples de percentuais com denominadores diferentes.', '',
        '| Política | Recompensa média ± DP entre sementes | Ações médias | Correções / positivos | Correções / tratáveis | Alterações indevidas |',
        '|---|---:|---:|---:|---:|---:|']
    for name,g in data.groupby('policy'):
        report.append(f'| {name} | {g.mean_reward.mean():.3f} ± {g.mean_reward.std():.3f} | {g.mean_actions.mean():.3f} | {g.validated_correction_rate.mean():.1%} | {g.treatable_correction_rate.mean():.1%} | {g.unnecessary_change_rate.mean():.1%} |')
    report += ['', '## Resultado de cada semente', '',
        '| Política | Semente | Correções validadas | Tratáveis | Positivos | Negativos | Ações em estados nunca visitados (Q) |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for e in cv['pooled']:
        m=e['metrics']
        unseen=str(m['unseen_state_actions']) if e['policy']=='q_learning' else 'N/A'
        report.append(f"| {e['policy']} | {e['seed']} | {m['validated']} | {m['treatable']} | {m['positives']} | {m['negatives']} | {unseen} |")
    report += ['', '## Interpretação e limites', '',
        'O Q-Learning aprendeu a selecionar as três transformações suportadas e empatou com regras na',
        'cobertura de correção, mas continuou inferior em recompensa e quantidade de ações.',
        'Não foi introduzido fallback por regras nem ajustado o treinamento para vencer a baseline.',
        'Os 35 arquivos incompatíveis com Python 3.11 ficam em um único grupo: quando esse',
        'grupo é teste, seus estados não existem no treino e a política tabular desempata',
        'valores zero escolhendo uma ação incompatível até o limite. O contador de estados',
        'não visitados registra esse comportamento. Casos incompatíveis não são removidos.', '',
        'O corpus foi inspecionado e já houve avaliação v1: esta é uma avaliação exploratória,',
        'não confirmação independente. Reparticionar dados conhecidos não os torna novos.',
        'Grupos são heurísticos e templates de sinks continuam compartilhados entre partições.',
        'As tarefas ainda são pequenas; cada caso oficial possui uma categoria rotulada, sem',
        'evidência de sequenciamento complexo entre várias correções no mesmo arquivo.',
        'Desvio entre sementes não é intervalo de confiança: os folds compartilham treinos.',
        '161 positivos oficiais incluem 116 sem transformação suportada; negativos: 293.',
        'Regressão funcional e sucesso completo são desconhecidos (null), não zero.', '',
        '## Detecção AST no corpus selecionado (separada da política)', '',
        '| CWE | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for c,m in cv['detection'].items():
        values=[str(m[k]) for k in ('tp','fp','tn','fn')]
        values += ['N/A' if m[k] is None else f'{m[k]:.3f}' for k in ('precision','recall','f1','fpr','fnr')]
        report.append(f'| {c} | '+' | '.join(values)+' |')
    report += ['', '## Artefatos', '',
        '- `datasets/manifests/folds.json`: todos os IDs, grupos e distribuições de cada partição.',
        '- `artifacts/metrics/cross_validation.json`: trajetórias por fold, semente e política.',
        '- `artifacts/metrics/cross_validation.csv`: resultados agregados por semente.',
        '- `artifacts/cross_validation/`: checkpoints, IDs de treino e históricos dos 12 treinamentos.',
        '- `artifacts/metrics/test.json`: holdout secundário do modelo demonstrativo, separado da CV.',
        '- `artifacts/plots/cv_*.png`: gráficos da avaliação cruzada.', '',
        'Os checkpoints da aplicação são escolhidos somente pela validação do modelo',
        'demonstrativo, nunca pela recompensa dos folds externos.']
    (ROOT/'docs/results.md').write_text('\n'.join(report)+'\n')


if __name__=='__main__':
    main()
