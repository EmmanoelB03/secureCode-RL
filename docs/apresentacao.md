# Roteiro de apresentação — SecureCode

1. **Problema:** apoiar a revisão de possíveis vulnerabilidades Python. Detecção e correção têm alcance limitado.
2. **Três módulos:** interface SvelteKit; IA TF-IDF + SVM para classificação e Q-Learning histórico para seleção de correções; resposta com previsão, indícios AST/Bandit e patch local validado.
3. **Dados:** 454 arquivos OWASP, 161 positivos e 293 negativos. Mostrar origem, rótulos e grupos. Nenhum código do usuário é executado.
4. **Experimento:** quatro folds por grupos, TF-IDF ajustado no treino; hiperparâmetros escolhidos na validação. Comparação com maioria e AST; limpeza dos IDs e rotas artificiais.
5. **Resultados:** AST F1 0,8653; regressão logística limpa 0,9032; SVM limpo 0,9112. Exibir também precision, recall, FP e FN. Não comparar esses números com taxas de correção do RL.
6. **Demonstração:** abrir `/`, carregar exemplo OWASP, analisar; explicar previsão versus localização de indícios. Solicitar correção e explicar que o Q-Learning seleciona transformações já implementadas. Mostrar `/dashboard` como avaliação histórica do RL.
7. **Erros:** selecionar exemplos com `y != pred` em `artifacts/supervised/evaluation.json`; mostrar ao lado de acertos da mesma CWE. Essas predições foram obtidas fora do treino; a previsão do modelo demonstrativo pode diferir. Não apresentar execução sobre dados de treino como evidência de generalização.
8. **Limitações:** benchmark conhecido, grupos heurísticos, nenhum dataset externo, sem equivalência funcional completa e sem garantia de segurança. Próximos passos: auditar similares entre grupos, validar em fonte externa e ampliar contratos de correção.

O modelo demonstrativo foi escolhido por macro-F1 na validação demonstrativa, não pela tabela de testes externos. A evolução do Q-Learning para classificação altera a tarefa investigada; ambas permanecem identificadas no sistema.
