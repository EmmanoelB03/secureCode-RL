# Resultados v2 — validação cruzada por grupos

Protocolo: `docs/expansion.md`. Resultados e código v1 preservados em `experiments/v1/`.
Corpus oficial: 454 casos, 26 grupos de fluxo, 4 folds.
Três sementes (42/43/44), 10.000 episódios por fold/semente, hiperparâmetros fixos.
Cada caso é avaliado uma vez fora do treino por semente. Nenhum grupo atravessa
treino, validação e teste da mesma rodada. A validação interna não inclui o teste.

## Cobertura real

| CWE | Casos | Positivos | Negativos | Transformáveis | Grupos transformáveis |
|---|---:|---:|---:|---:|---:|
| 89 | 16 | 5 | 11 | 5 | 4 |
| 78 | 20 | 13 | 7 | 0 | 0 |
| 94 | 53 | 20 | 33 | 0 | 0 |
| 614 | 39 | 24 | 15 | 22 | 13 |
| 330 | 326 | 99 | 227 | 18 | 9 |

Total de candidatos: 45, contra 5 na v1.
Certificados locais: parametrização SQL, atributo Secure de cookie e fonte de
aleatoriedade do SO para bytes. Cookies exigem HTTPS; nenhum certificado cobre
equivalência funcional do programa inteiro ou o protocolo completo de autenticação.

## Partições (total / tratáveis)

| Fold | Treino | Validação | Teste |
|---|---:|---:|---:|
| 1 | 262 / 24 | 96 / 12 | 96 / 9 |
| 2 | 217 / 20 | 141 / 13 | 96 / 12 |
| 3 | 192 / 21 | 121 / 11 | 141 / 13 |
| 4 | 237 / 25 | 96 / 9 | 121 / 11 |

## Agregação fora do treino

As métricas são calculadas concatenando trajetórias dos folds por semente, não
fazendo média simples de percentuais com denominadores diferentes.

| Política | Recompensa média ± DP entre sementes | Ações médias | Correções / positivos | Correções / tratáveis | Alterações indevidas |
|---|---:|---:|---:|---:|---:|
| q_learning | -2.905 ± 0.000 | 1.584 | 28.0% | 100.0% | 0.0% |
| random | -21.772 ± 0.240 | 4.079 | 1.9% | 6.7% | 0.0% |
| rule_based | -0.207 ± 0.000 | 1.198 | 28.0% | 100.0% | 0.0% |

## Resultado de cada semente

| Política | Semente | Correções validadas | Tratáveis | Positivos | Negativos | Ações em estados nunca visitados (Q) |
|---|---:|---:|---:|---:|---:|---:|
| random | 42 | 3 | 45 | 161 | 293 | N/A |
| rule_based | 42 | 45 | 45 | 161 | 293 | N/A |
| q_learning | 42 | 45 | 45 | 161 | 293 | 210 |
| random | 43 | 2 | 45 | 161 | 293 | N/A |
| rule_based | 43 | 45 | 45 | 161 | 293 | N/A |
| q_learning | 43 | 45 | 45 | 161 | 293 | 210 |
| random | 44 | 4 | 45 | 161 | 293 | N/A |
| rule_based | 44 | 45 | 45 | 161 | 293 | N/A |
| q_learning | 44 | 45 | 45 | 161 | 293 | 210 |

## Interpretação e limites

O Q-Learning aprendeu a selecionar as três transformações suportadas e empatou com regras na
cobertura de correção, mas continuou inferior em recompensa e quantidade de ações.
Não foi introduzido fallback por regras nem ajustado o treinamento para vencer a baseline.
Os 35 arquivos incompatíveis com Python 3.11 ficam em um único grupo: quando esse
grupo é teste, seus estados não existem no treino e a política tabular desempata
valores zero escolhendo uma ação incompatível até o limite. O contador de estados
não visitados registra esse comportamento. Casos incompatíveis não são removidos.

O corpus foi inspecionado e já houve avaliação v1: esta é uma avaliação exploratória,
não confirmação independente. Reparticionar dados conhecidos não os torna novos.
Grupos são heurísticos e templates de sinks continuam compartilhados entre partições.
As tarefas ainda são pequenas; cada caso oficial possui uma categoria rotulada, sem
evidência de sequenciamento complexo entre várias correções no mesmo arquivo.
Desvio entre sementes não é intervalo de confiança: os folds compartilham treinos.
161 positivos oficiais incluem 116 sem transformação suportada; negativos: 293.
Regressão funcional e sucesso completo são desconhecidos (null), não zero.

## Detecção AST no corpus selecionado (separada da política)

| CWE | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 89 | 5 | 0 | 11 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| 78 | 13 | 7 | 0 | 0 | 0.650 | 1.000 | 0.788 | 1.000 | 0.000 |
| 94 | 19 | 30 | 3 | 1 | 0.388 | 0.950 | 0.551 | 0.909 | 0.050 |
| 614 | 22 | 0 | 15 | 2 | 1.000 | 0.917 | 0.957 | 0.000 | 0.083 |
| 330 | 92 | 0 | 227 | 7 | 1.000 | 0.929 | 0.963 | 0.000 | 0.071 |

## Artefatos

- `datasets/manifests/folds.json`: todos os IDs, grupos e distribuições de cada partição.
- `artifacts/metrics/cross_validation.json`: trajetórias por fold, semente e política.
- `artifacts/metrics/cross_validation.csv`: resultados agregados por semente.
- `artifacts/cross_validation/`: checkpoints, IDs de treino e históricos dos 12 treinamentos.
- `artifacts/metrics/test.json`: holdout secundário do modelo demonstrativo, separado da CV.
- `artifacts/plots/cv_*.png`: gráficos da avaliação cruzada.

Os checkpoints da aplicação são escolhidos somente pela validação do modelo
demonstrativo, nunca pela recompensa dos folds externos.
