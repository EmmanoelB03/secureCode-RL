# Protocolo v2 — cobertura e validação cruzada

Definido após inspeção do corpus e antes dos novos treinamentos. V1 preservada em
`experiments/v1/` (fontes, configuração, corpus processado, manifestos e resultados).
Não se comparam recompensas v1/v2 como se fossem o mesmo ambiente.

O corpus continua oficial, no mesmo commit OWASP; nenhum exemplo sintético é
adicionado aos experimentos. São incluídos todos os positivos e negativos de
CWE-614 e CWE-330, além das três categorias anteriores: **454 exemplos**.

| CWE | Total | Positivos | Negativos | Positivos transformáveis em Python 3.11 |
|---|---:|---:|---:|---:|
| 89 | 16 | 5 | 11 | 5 |
| 78 | 20 | 13 | 7 | 0 |
| 94 | 53 | 20 | 33 | 0 |
| 614 | 39 | 24 | 15 | 22 |
| 330 | 326 | 99 | 227 | 18 |

Total: **45 candidatos**, contra 5 na v1. Nenhum negativo oficial corresponde aos
três padrões de transformação. Isso não comprova ausência de falsos positivos fora
desse corpus. IDs, hashes, grupos, cobertura e incompatibilidades estão nos manifestos.

## Transformações e propriedades

- SQL: parametrização SQLite restrita, mantendo as condições da v1.
- Cookie: `secure=False` passa a `True` na chamada de uma resposta construída por
  `flask.make_response`. Todos os outros argumentos permanecem. **Requer HTTPS**;
  cookies deixam de ser enviados via HTTP. Texto descritivo do benchmark é preservado
  e pode continuar mencionando o valor antigo; não é parte do certificado.
- Aleatoriedade: somente `random.randbytes(32)` vira
  `random.SystemRandom().randbytes(32)`, preservando tipo bytes e comprimento 32.
  Verifica a seleção da fonte de entropia do SO, não todo o protocolo de autenticação,
  armazenamento ou tratamento posterior do token. Chamadas com 32 bits, floats ou
  distribuição normal não são convertidas: mudar o gerador não resolve por si só
  o tamanho do segredo e pode alterar contratos.

Comparação AST permite exclusivamente a alteração especificada. Testes executam
apenas bibliotecas confiáveis em um harness próprio, jamais arquivos do benchmark.
Não há bônus por equivalência funcional completa; ela permanece desconhecida.
O estado e a Q-Table passam para schema 2, com sete ações, incluindo as duas novas.

XXE foi investigado: habilitar entidades externas aparece em 6 positivos analisáveis
e também em 7 negativos. Sem provar a relevância do fluxo, a alteração criaria
modificações indevidas. Não incluído. Hash exige contrato de migração de digest;
Path Traversal exige raiz e política de acesso. Permanecem fora. A ampliação no
mesmo corpus evita misturar protocolos de rotulagem de outras fontes nesta rodada;
não equivale a diversidade independente entre projetos.

## Avaliação congelada

Validação cruzada de **quatro folds por grupo**. Há somente quatro grupos de fluxo
entre os cinco SQL positivos; cinco folds não garantiriam SQL positivo em cada fold.
Agrupamento AST conservador entre CWEs, normalizando variantes geradas; não são IDs
oficiais de templates. Todos os arquivos incompatíveis ficam no mesmo grupo.

Cada rodada usa um fold como teste, o próximo como validação e os dois restantes
como treino. Nenhum grupo atravessa partições da mesma rodada. Cada exemplo é
testado **uma vez por semente**. São executadas as sementes 42/43/44, com política
aleatória e por regras nas mesmas partições, ações, orçamento e recompensas.

Hiperparâmetros mantidos em 10.000 episódios, alpha=.1, gamma=.95 e decay=.995;
esta rodada isola a ampliação dos dados/ações e o protocolo, sem busca para vencer
baselines. Validação interna é registrada; os resultados externos não selecionam
hiperparâmetros nem checkpoint da aplicação. O modelo demonstrável usa a separação
train/validation/test v2, com escolha apenas na validação. A comparação principal é CV.

Relatar cobertura de estados, resultados por fold/CWE e métricas agregadas a partir
de trajetórias fora do treino. Desvio entre sementes não é intervalo de confiança;
folds têm treinos sobrepostos. Como o corpus já foi inspecionado e a v1 já foi
avaliada, **esta CV é exploratória, não confirmação independente**. Mais grupos e
projetos externos ainda seriam necessários para conclusões amplas.

Referências: [Python SystemRandom](https://docs.python.org/3/library/random.html#random.SystemRandom),
[Flask set_cookie](https://flask.palletsprojects.com/en/stable/api/#flask.Response.set_cookie),
[validação por grupos](https://scikit-learn.org/stable/modules/cross_validation.html#stratifiedgroupkfold).
