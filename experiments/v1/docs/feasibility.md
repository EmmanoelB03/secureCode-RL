# Inspeção e escopo congelado antes do treinamento

Origem: https://github.com/OWASP-Benchmark/BenchmarkPython, versão 0.1,
commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. A fonte é um benchmark
OWASP de **detecção**, não um corpus de patches ou testes de equivalência funcional.
Não há evidência aqui de validação acadêmica independente de cada patch.
Os 1.230 rótulos foram lidos do CSV oficial, sem alteração. Manifestos registram
hashes, IDs, caminhos, grupos e partições. Código do benchmark nunca é importado.

| CWE | Positivos | Negativos | Candidatos à transformação |
|---|---:|---:|---:|
| 89 | 5 | 11 | 5 |
| 78 | 13 | 7 | 0 |
| 94 | 20 | 33 | 0 |

A única transformação admitida é substituir a chamada `cur.execute(sql)` do
bloco SQLite específico por uma consulta constante com parâmetro separado.
A variável `sql` original permanece para preservar os outros usos do programa.
Uma comparação AST verifica que somente os argumentos aprovados foram alterados.
O certificado se limita à separação de parâmetros na chamada, assumindo o contrato
SQLite do helper oficial. Não certifica o comportamento de um módulo externo
arbitrário com o mesmo nome, nem equivalência funcional do programa inteiro.
Testes controlados usam SQLite em memória e consultas escritas pelos desenvolvedores;
nenhum trecho recebido ou do dataset é executado.

Command Injection utiliza shells explícitos, comandos dependentes do sistema e
tratamento de saída. Remover o shell não preserva necessariamente o comportamento.
Code Injection exige executar instruções arbitrárias por design; trocar `exec` por
`literal_eval` não é uma correção funcionalmente equivalente. Ambas permanecem na
detecção e na avaliação de abstenção; suas ações retornam `unsupported`.
Path Traversal foi considerado: exigiria definir raízes permitidas e comportamento
para acessos legítimos fora delas. Não foi adicionado sem esse contrato.

Os 89 casos são agrupados por AST do fluxo intermediário, normalizando nomes
gerados e constantes, ignorando fonte e sink. Grupos atravessam CWEs, mas nunca
partições. É uma heurística conservadora, não prova de ausência de similaridade:
os IDs originais de template não estão disponíveis. Distribuição: 59 treino,
16 validação, 14 teste; SQL positivo: 3/1/1. O holdout é minúsculo e não permite
alegações de generalização robusta. Não há ajuste de hiperparâmetros pelo teste.

Alguns arquivos usam f-strings aceitas a partir do Python 3.12. Sob Python 3.11,
são preservados e marcados incompatíveis (lista em `coverage.json`), nunca corrigidos
silenciosamente. Mudar o interpretador pode mudar a análise; reproduzir com 3.11.

O problema experimental resultante é pequeno: aprender FIX_SQL → VALIDATE → STOP,
e abster-se nos demais casos. Não permite estudar sequências entre três correções
distintas. As cinco ações são preservadas para medir incompatibilidades.
Um resultado favorável não demonstra capacidade geral de reparo de código.

Validação funcional completa fica desconhecida: sem bônus +3 nem bônus máximo +15.
A recompensa +10 refere-se somente à propriedade SQL local validada. Regressão
funcional e sucesso completo são `null` nas métricas quando não verificáveis.
As taxas de correção especificam seu denominador, separadas da detecção.
