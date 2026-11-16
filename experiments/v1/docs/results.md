# Resultados observados

Protocolo congelado antes do treino: `docs/feasibility.md`. Três sementes de 10.000 episódios,
59 casos de treinamento, 16 de validação, 14 de teste. Todos os agentes usam os mesmos
casos, orçamento e recompensas. Não houve ajuste pelo teste.

| Política | Recompensa média ± DP entre sementes | Ações médias | Correções / positivos | Correções / tratáveis |
|---|---:|---:|---:|---:|
| q_learning | -10.429 ± 0.000 | 2.571 | 20.0% | 100.0% |
| random | -16.833 ± 2.620 | 3.405 | 0.0% | 0.0% |
| rule_based | -0.429 ± 0.000 | 1.143 | 20.0% | 100.0% |

O Q-Learning e a baseline por regras validaram a parametrização do único SQL positivo
do teste em todas as sementes. Há cinco positivos oficiais ao todo, quatro sem correção
suportada. O agente aleatório não chegou a uma correção validada nessas três execuções.
Nenhum agente alterou negativos. Esses resultados não medem equivalência funcional.

O Q-Learning foi inferior às regras em recompensa e número de ações. Os quatro arquivos
com sintaxe não aceita pelo Python 3.11 estão no teste e geram estados ausentes do treino.
A Q-Table inicia em zero; o desempate determinístico por menor índice insiste na ação SQL
incompatível nesses estados até o limite do episódio. Essa limitação foi preservada, sem
introduzir uma regra de fallback depois de observar o teste.

O desvio padrão entre sementes não é intervalo de confiança nem evidência de generalização.
Só há um caso tratável no teste; não é possível concluir eficácia ampla de reparo.

## Detecção AST separada

| CWE | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 89 | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| 78 | 1 | 1 | 0 | 0 | 0.500 | 1.000 | 0.667 | 1.000 | 0.000 |
| 94 | 2 | 4 | 3 | 1 | 0.333 | 0.667 | 0.444 | 0.571 | 0.333 |

O analisador é conservador, sem análise completa de taint. Casos sintaticamente
incompatíveis não geram detecção e contam normalmente na matriz; não são excluídos
para elevar métricas. Bandit não está incluído nessa matriz.

## Artefatos

- `artifacts/metrics/test.json`: trajetórias por caso, rótulos oficiais e resumos por CWE.
- `artifacts/metrics/test.csv`: tabela por política e semente.
- `artifacts/metrics/history-*.csv`: todos os episódios, recompensas e epsilon.
- `artifacts/checkpoints/q-seed-*.npz`: tabelas e metadados, sem pickle.
- `artifacts/plots/`: recompensa, epsilon, correções, agentes, categorias e ações.

Regressões funcionais e sucesso completo permanecem desconhecidos. Não foi executada
a aplicação vulnerável nem código recebido do usuário.
