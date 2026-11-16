# Protocolo de classificação supervisionada

Status: **pré-registro da avaliação inicial**. Congelar antes de consultar resultados de teste. Revisão exploratória planejada para o corpus disponível; não representa validação externa independente.

## Pergunta e unidade

Pergunta: um classificador TF-IDF treinado em arquivos do OWASP Benchmark Python identifica arquivos rotulados como vulneráveis melhor do que a regra AST atual e uma baseline majoritária, em famílias de fluxo mantidas fora do treino?

Unidade: um arquivo Python do subconjunto local de 454 exemplos. Classe positiva significa exclusivamente `vulnerable=true` no rótulo oficial para as categorias incluídas (CWE-89, 78, 94, 614 e 330); negativa significa o rótulo oficial negativo. A classe não afirma segurança geral. Não haverá classificação multiclasse CWE nesta rodada.

## Dados e rastreabilidade

Fonte: OWASP Benchmark for Python 0.1, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Preservar ID, fonte, rótulo, categoria e hash no manifesto; estes metadados não entram como atributos do modelo. Conferir que os 454 arquivos locais correspondem às fontes e rótulos oficiais. Não executar os arquivos.

Antes do treino, produzir auditoria de comentários, docstrings, nomes de identificadores, marcadores explícitos de vulnerabilidade, arquivos incompatíveis com parser, duplicatas exatas e duplicatas após normalização. Inspecionar colisões entre grupos AST e duplicatas. Se a normalização criar grupos que atravessam folds, congelar uma atribuição agrupada nova antes de treinar e registrar o hash do manifesto; não modificar partições após observar métricas.

## Representações

Comparar duas condições diagnósticas:

1. **Bruta:** código fonte, sem metadados externos.
2. **Limpa:** remover comentários e docstrings por transformação sintática; normalizar apenas identificadores que a auditoria mostrar serem identificadores dos casos ou pistas geradas. Preservar chamadas/API relevantes (`execute`, `eval`, `set_cookie`), estrutura, literais e identificadores sem evidência de vazamento. Não remover texto condicionalmente ao rótulo.

Preservar o código original; armazenar a representação e método de pré-processamento com versão e hash. Para erro de sintaxe, manter o caso e registrar explicitamente a política definida após a auditoria; nunca descartá-lo silenciosamente. Comparar duplicatas exatas e hashes após ambas as representações.

## Partições e seleção

Auditar os grupos AST atuais antes de reutilizá-los. Usar quatro folds externos por grupos se viável; em cada rodada, um grupo-fold é teste, o seguinte é validação e os restantes são treino. Cada exemplo fica no teste uma vez. Garantir nenhuma interseção de grupos ou conteúdo duplicado entre treino, validação e teste. Registre todos os IDs, grupos e SHA-256 do manifesto antes da avaliação.

Para cada fold, ajustar TF-IDF apenas no treino. Selecionar regularização/configuração somente por macro-F1 interno no conjunto de validação; a métrica principal reportada é F1 da classe positiva. Não selecionar modelo, limiar, limpeza ou hiperparâmetro com teste externo. Usar limiar 0,5 para Regressão Logística e limiar de decisão padrão para LinearSVC, sem busca de limiar no teste.

## Modelos e baselines

- Baseline majoritária, ajustada no treino da rodada.
- Regra AST existente convertida para positivo quando detectar ao menos um CWE do escopo; negativa caso contrário. Bandit fica fora desta regra se não fizer parte do detector existente.
- TF-IDF de unigramas e bigramas de tokens de código + Regressão Logística, `class_weight` em `{None, balanced}` e `C` em `{0.1, 1, 10}`.
- TF-IDF da mesma configuração + LinearSVC, mesmo conjunto limitado de `class_weight` e `C`.

Ajuste no máximo seis combinações por classificador e representação. O vocabulário é aprendido dentro de cada treino. LinearSVC fornece margem, não probabilidade; não exibir sua margem como confiança.

## Métricas e relatório

Relatar por fold e sobre predições externas concatenadas: precision, recall, F1 positivo (principal), macro-F1, balanced accuracy e matriz de confusão. Separar falsos positivos e falsos negativos; apresentar F1/precision/recall por CWE apenas como análise descritiva binária, com denominadores. Comparar as predições da regra AST e baseline nos mesmos exemplos. Salvar predições OOF por ID, classe verdadeira, predição, fold e CWE, sem usar IDs como atributos.

Medir inferência sobre os mesmos exemplos após aquecimento: cinco repetições do conjunto, reportando mediana por arquivo e método. Registrar versão Python/scikit-learn, sementes, configuração, hashes de fonte, dados, grupos e artefatos. Avaliação de limpeza é uma comparação diagnóstica; a condição bruta não pode ser escolhida para servir a aplicação se a auditoria revelar vazamento.

## Critério de decisão e limitações

Só recomendar integração se houver benefício útil frente à regra AST nas predições fora do treino, sem vazamento identificado e considerando explicitamente precision/recall. Se resultados forem inconclusivos ou piores, manter a alternativa como experimento e preservar Q-Learning na aplicação. Não comparar F1 de classificação com taxa de correção do Q-Learning: medem tarefas distintas.

O corpus já foi inspecionado e usado em experimentos anteriores; os resultados são exploratórios. Quatro folds pequenos e agrupamentos heurísticos não comprovam generalização para outros projetos. Classificação negativa significa apenas “não identificado pelo modelo”. Qualquer avaliação externa precisa de outra fonte com licença e rótulos compatíveis, sem duplicatas, e modelo congelado antes de consultá-la.
