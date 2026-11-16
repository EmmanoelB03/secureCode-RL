# Resultados supervisionados — avaliação exploratória

Execução concluída sobre 454 arquivos. Cada política possui uma predição fora do treino por ID. Quatro folds por grupos; seleção por macro-F1 na validação interna, seguida de reajuste em treino + validação antes da inferência externa. O teste não seleciona hiperparâmetros.

| Representação | Política | Precision | Recall | F1 positivo | FP | FN |
|---|---|---:|---:|---:|---:|---:|
| raw | majority | 0.0000 | 0.0000 | 0.0000 | 0 | 161 |
| raw | ast_rules | 0.8032 | 0.9379 | 0.8653 | 37 | 10 |
| raw | logistic | 0.8278 | 0.9255 | 0.8739 | 31 | 12 |
| raw | linearsvc | 0.8500 | 0.9503 | 0.8974 | 27 | 8 |
| cleaned | majority | 0.0000 | 0.0000 | 0.0000 | 0 | 161 |
| cleaned | ast_rules | 0.8032 | 0.9379 | 0.8653 | 37 | 10 |
| cleaned | logistic | 0.8556 | 0.9565 | 0.9032 | 26 | 7 |
| cleaned | linearsvc | 0.8701 | 0.9565 | 0.9112 | 23 | 7 |

## Interpretação

O resultado inicial favorece a representação normalizada: ambos os classificadores melhoram precision e recall em relação às regras AST neste corpus. LinearSVC limpo alcança F1 0,9112, frente a 0,8653 das regras, reduzindo falsos positivos de 37 para 23 e falsos negativos de 10 para 7. Isso apoia continuar a investigação e integração, mas não constitui confirmação independente nem permite escolher o modelo de produção pelos testes externos.

A versão anterior tinha um erro de agregação: somente o classificador vencedor em cada fold era avaliado. A correção avalia cada família nos quatro folds, garantindo 454 IDs distintos por política/representação.

## Limitações e pendências

- O corpus já era conhecido; não há avaliação externa independente.
- Normalização remove comentários/docstrings e substitui IDs BenchmarkTest, rotas de categoria e sufixos gerados longos. Os nomes das APIs são preservados. Literais com sufixos semelhantes também podem mudar: avaliar esse limite antes de servir a transformação como ferramenta geral.
- Tokenização conserva os 35 arquivos incompatíveis com AST Python 3.11; não há fallback para código bruto nem exclusão desses casos.
- A auditoria inicial em audit.json precede esta normalização; a checagem adicional de hashes normalizados impede colisões entre partições, mas similaridade aproximada ainda requer investigação.
- Tempos registrados são de uma chamada em lote, sem aquecimento; não são um benchmark de latência confiável. Baselines têm tempo ausente, representado como zero pelo resumo atual; não interpretar como execução instantânea.
- API, frontend e modelo persistido supervisionado ainda não foram implementados; o Q-Learning continua em uso.

## Reprodução

```bash
.venv/bin/pip install -r requirements.supervised.txt
.venv/bin/python scripts/audit_supervised.py
.venv/bin/python training/supervised.py
```

Artefatos: artifacts/supervised/evaluation.json contém trajetórias de predições, configurações por fold e métricas por CWE. datasets/manifests/supervised/folds.json preserva as partições e o hash do script.

## Integração demonstrativa

O script `training/fit_supervised.py` seleciona entre as duas famílias e seis
configurações por família na validação demonstrativa, sem ler testes ou métricas CV.
Escolha observada: LinearSVC, C=1, class_weight=balanced, macro-F1 de validação 0,9286.
Reajuste final usa train+validation. Pipeline e metadados ficam em model.joblib/model.json.

A API `/api/v1/analyze` retorna `classification` junto de AST e Bandit. A interface
apresenta previsão, modelo, versão e aviso, e mostra divergências com AST. Q-Learning
continua selecionando correções. A integração não equivale a confirmação externa.
As pendências metodológicas listadas acima (similaridade aproximada e latência)
continuam abertas; a integração substitui a antiga indicação de que API e frontend
ainda não estavam implementados.
