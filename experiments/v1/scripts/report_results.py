"""Generate a factual report exclusively from recorded experiment outputs."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd
from backend.app.datasets.core import ROOT


def main():
    data = pd.read_csv(ROOT / 'artifacts/metrics/test.csv')
    report = ['# Resultados observados', '',
        'Protocolo congelado antes do treino: `docs/feasibility.md`. Três sementes de 10.000 episódios,',
        '59 casos de treinamento, 16 de validação, 14 de teste. Todos os agentes usam os mesmos',
        'casos, orçamento e recompensas. Não houve ajuste pelo teste.', '',
        '| Política | Recompensa média ± DP entre sementes | Ações médias | Correções / positivos | Correções / tratáveis |',
        '|---|---:|---:|---:|---:|']
    for name, group in data.groupby('policy'):
        report.append(f'| {name} | {group.mean_reward.mean():.3f} ± {group.mean_reward.std():.3f} | {group.mean_actions.mean():.3f} | {group.validated_correction_rate.mean():.1%} | {group.treatable_correction_rate.mean():.1%} |')
    report += ['',
        'O Q-Learning e a baseline por regras validaram a parametrização do único SQL positivo',
        'do teste em todas as sementes. Há cinco positivos oficiais ao todo, quatro sem correção',
        'suportada. O agente aleatório não chegou a uma correção validada nessas três execuções.',
        'Nenhum agente alterou negativos. Esses resultados não medem equivalência funcional.', '',
        'O Q-Learning foi inferior às regras em recompensa e número de ações. Os quatro arquivos',
        'com sintaxe não aceita pelo Python 3.11 estão no teste e geram estados ausentes do treino.',
        'A Q-Table inicia em zero; o desempate determinístico por menor índice insiste na ação SQL',
        'incompatível nesses estados até o limite do episódio. Essa limitação foi preservada, sem',
        'introduzir uma regra de fallback depois de observar o teste.', '',
        'O desvio padrão entre sementes não é intervalo de confiança nem evidência de generalização.',
        'Só há um caso tratável no teste; não é possível concluir eficácia ampla de reparo.', '',
        '## Detecção AST separada', '',
        '| CWE | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    metrics = json.loads((ROOT / 'artifacts/metrics/test.json').read_text())
    for cwe, m in metrics['detection'].items():
        vals = [str(m[k]) for k in ('tp','fp','tn','fn')]
        vals += ['N/A' if m[k] is None else f'{m[k]:.3f}' for k in ('precision','recall','f1','fpr','fnr')]
        report.append(f'| {cwe} | ' + ' | '.join(vals) + ' |')
    report += ['', 'O analisador é conservador, sem análise completa de taint. Casos sintaticamente',
        'incompatíveis não geram detecção e contam normalmente na matriz; não são excluídos',
        'para elevar métricas. Bandit não está incluído nessa matriz.', '',
        '## Artefatos', '',
        '- `artifacts/metrics/test.json`: trajetórias por caso, rótulos oficiais e resumos por CWE.',
        '- `artifacts/metrics/test.csv`: tabela por política e semente.',
        '- `artifacts/metrics/history-*.csv`: todos os episódios, recompensas e epsilon.',
        '- `artifacts/checkpoints/q-seed-*.npz`: tabelas e metadados, sem pickle.',
        '- `artifacts/plots/`: recompensa, epsilon, correções, agentes, categorias e ações.', '',
        'Regressões funcionais e sucesso completo permanecem desconhecidos. Não foi executada',
        'a aplicação vulnerável nem código recebido do usuário.']
    (ROOT / 'docs/results.md').write_text('\n'.join(report) + '\n')


if __name__ == '__main__':
    main()
