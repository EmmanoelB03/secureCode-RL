Pode mandar o texto abaixo para o Luna. O plano preserva o projeto atual e exige evidência antes de substituir o Q-Learning.

---

Você trabalhará no projeto **SecureCode RL**, em `/home/emmanoel/projects/trabalho_IA`.

O objetivo é investigar e implementar uma evolução para **detecção assistida de possíveis vulnerabilidades em Python com classificação supervisionada**, reaproveitando a aplicação existente.

O professor exige:

- Módulo de interface com o usuário.
- Módulo de IA.
- Módulo de resposta.
- Apresentação do sistema e código disponível no GitHub.

Q-Learning não é obrigatório. Temos aproximadamente sete dias para concluir.

### 1. Regras gerais

Antes de alterar arquivos, leia as instruções locais aplicáveis, `README.md`, `plan.md` e a documentação em `docs/`.

Inspecione a implementação para confirmar as informações abaixo:

- Backend FastAPI e frontend SvelteKit funcionando.
- Dataset OWASP Benchmark Python, com 454 exemplos selecionados de cinco CWEs.
- Analisador AST e integração Bandit.
- Três transformações restritas: SQL, cookies Secure e aleatoriedade.
- Q-Learning, baselines, checkpoints e resultados experimentais.
- Testes automatizados e script de integração web.

Requisitos de execução:

- Preserve o projeto atual e seus resultados.
- Não sobrescreva checkpoints ou métricas do Q-Learning.
- Não substitua dados reais por exemplos sintéticos nos experimentos.
- Não execute código recebido do usuário nem módulos vulneráveis do benchmark.
- Não altere rótulos oficiais.
- Não invente resultados nem apresente probabilidades como certeza.
- Não remova o Q-Learning antes de avaliar a alternativa.
- Faça escolhas rotineiras autonomamente e documente decisões e limitações.
- Não publique, envie alterações ao GitHub ou crie uma release sem autorização explícita.

### 2. Definir a tarefa e preservar a referência

Crie um protocolo em `docs/supervised-protocol.md` contendo:

- Pergunta experimental.
- Dataset e escopo.
- Unidade de classificação.
- Pré-processamento.
- Divisão dos dados.
- Modelos e baselines.
- Métricas.
- Critérios de seleção.
- Limitações conhecidas.

A tarefa inicial será **classificação binária de um arquivo: presença ou ausência de vulnerabilidade conforme o rótulo oficial, dentro das categorias selecionadas**.

Não começar com classificação multiclasse por CWE nem redes neurais.

Preserve uma referência recuperável da versão atual, usando Git se disponível ou um snapshot organizado dos arquivos necessários. Evite copiar ambientes virtuais, dependências e builds.

Guarde os novos artefatos em diretórios separados, por exemplo:

```text
artifacts/supervised/
datasets/manifests/supervised/
```

Registre hashes, sementes, versões e configurações.

### 3. Auditar os dados e evitar vazamento

Investigue se existem pistas que permitiriam prever o rótulo sem analisar características relevantes do código:

- Comentários e docstrings explicativos.
- Identificadores dos casos.
- Nomes de funções e rotas derivados do benchmark.
- Referências explícitas à vulnerabilidade.
- Trechos repetidos ou quase duplicados.
- Famílias de código compartilhadas entre partições.

Crie uma representação para treinamento que remova ou normalize pistas artificiais justificadas pela inspeção.

Cuidados:

- Preserve o código original para exibição e rastreabilidade.
- Preserve nomes de APIs relevantes, como `execute`, `eval` e `set_cookie`.
- Não normalize indiscriminadamente todos os identificadores e literais.
- Nunca use CWE oficial, ID, nome do arquivo, rótulo ou resultado do validador como entrada do classificador.
- Não use rótulos para decidir como limpar cada arquivo individualmente.
- Documente exemplos do antes e depois do pré-processamento.
- Defina tratamento explícito para arquivos incompatíveis com o parser, sem removê-los silenciosamente.

Verifique também duplicatas após o pré-processamento. Registre conflitos com os agrupamentos existentes e resolva-os antes dos experimentos.

### 4. Congelar o protocolo de avaliação

Use separação por grupos para reduzir a presença de variantes semelhantes em treino e avaliação.

Reaproveite os grupos existentes somente após verificar sua adequação à nova tarefa.

Regras obrigatórias:

- Ajustar TF-IDF exclusivamente no treino de cada rodada.
- Escolher hiperparâmetros e limiar de decisão somente em treino/validação interna.
- Não usar o teste externo para selecionar o modelo.
- Aplicar a mesma partição e os mesmos exemplos às baselines.
- Registrar os IDs e grupos de cada partição.
- Não mudar partições porque algum resultado foi ruim.
- Tratar o corpus atual como avaliação exploratória, pois já foi inspecionado anteriormente.

Uma opção é manter quatro folds por grupos, reservando um para teste, outro para validação e os restantes para treino, se a auditoria confirmar a viabilidade.

Defina antecipadamente o procedimento de seleção e a métrica principal, sugerindo **F1 da classe vulnerável**, acompanhado obrigatoriamente de precision e recall.

### 5. Implementar modelos simples

Implemente pipelines reproduzíveis com scikit-learn:

1. Baseline que sempre prevê a classe majoritária.
2. Regras AST existentes, convertidas em uma decisão binária documentada.
3. TF-IDF + Regressão Logística.
4. TF-IDF + LinearSVC.

Comece com uma configuração pequena de TF-IDF baseada em tokens de código e poucos hiperparâmetros. Limite previamente a busca; evite dezenas de tentativas guiadas pelos resultados externos.

Avalie `class_weight` e regularização na validação interna.

Não compare diretamente o F1 dos classificadores com a taxa de correção do Q-Learning: são tarefas diferentes.

O LinearSVC não fornece probabilidades diretamente. Não transforme sua margem em porcentagem de confiança. Se houver calibração, ela deve ocorrer apenas com dados internos adequados.

### 6. Avaliar e decidir

Gere:

- Precision, recall e F1 da classe vulnerável.
- Macro-F1 e acurácia balanceada.
- Matriz de confusão.
- Falsos positivos e falsos negativos.
- Métricas por CWE, preservando a tarefa binária.
- Resultados por fold e agregados.
- Predições fora do treino por exemplo.
- Tempo de inferência, com método de medição documentado.

Compare todos os modelos com as regras AST e a baseline majoritária.

Investigue erros representativos sem ajustar o modelo repetidamente ao teste. Diferencie explicações observadas de hipóteses.

Faça uma análise controlada do impacto da limpeza de pistas artificiais, sem usar a configuração com vazamento como candidata para a aplicação.

Crie `docs/supervised-results.md` com uma conclusão honesta:

- O classificador acrescenta algo às regras?
- Em quais categorias?
- Quais erros persistem?
- Há evidência de aprendizagem de peculiaridades do benchmark?
- O resultado permite justificar a troca do módulo principal?

**Critério de decisão:** a integração principal só deve ocorrer se a avaliação sustentar uma contribuição útil. Não é obrigatório superar as regras em toda métrica, mas qualquer troca entre precision e recall precisa ser explícita.

Se o resultado for fraco, preserve a aplicação atual e documente a alternativa como experimento. Não esconda um resultado negativo.

### 7. Investigar generalização externa

Se houver tempo, procure dados públicos independentes compatíveis com a tarefa.

Antes de incorporar outra fonte:

- Verifique licença, origem e significado dos rótulos.
- Verifique compatibilidade com a unidade de classificação.
- Investigue duplicatas e sobreposição com o treino.
- Separe dados com vulnerabilidade confirmada de código apenas presumido seguro.
- Congele o modelo antes da avaliação externa.

Não acrescente um dataset apenas para aumentar a quantidade. Se não houver fonte adequada no prazo, registre que a generalização externa não foi demonstrada.

### 8. Integrar o modelo quando justificado

Se a decisão experimental for favorável, integre o classificador preservando funções distintas:

```text
Código Python
    ├── Classificador → previsão do arquivo
    ├── AST/Bandit → indícios e linhas suspeitas
    └── Transformações + validadores → correções locais disponíveis
```

No backend:

- Carregue um pipeline treinado e versionado.
- Reutilize exatamente o pré-processamento do treinamento.
- Valide tamanho e formato da entrada.
- Retorne previsão, versão do modelo e limitações.
- Informe erros de artefato ausente ou incompatível.
- Não treine durante uma requisição.
- Carregue somente artefatos confiáveis produzidos pelo projeto.

Na interface:

- Apresente “possível vulnerabilidade” ou “não identificada pelo modelo”.
- Não apresente “código seguro”.
- Distinga previsão do modelo, alertas AST/Bandit e correções.
- Não atribua ao classificador as linhas indicadas pelas regras.
- Mostre divergências entre modelo e analisadores sem ocultá-las.
- Se exibir probabilidades, esclareça sua interpretação e limitações.
- Mantenha a comparação entre código original e proposta.
- Separe os resultados supervisionados dos experimentos históricos de RL.

Se Q-Learning sair do fluxo principal, descreva explicitamente como as correções passam a ser selecionadas. Não chame transformações determinísticas de correções aprendidas pelo classificador.

### 9. Testar e documentar

Execute os testes existentes e adicione testes relevantes para:

- Pré-processamento consistente.
- Remoção das pistas artificiais identificadas.
- Ausência de sobreposição de grupos.
- Carregamento e inferência do pipeline.
- Contrato da API.
- Entrada inválida e modelo indisponível.
- Garantia de que o código submetido não é executado.

Execute a checagem e o build do frontend e a integração HTTP. Verifique o fluxo visível no navegador quando houver ferramenta disponível.

Atualize a documentação com:

- Instalação e execução.
- Preparação dos dados.
- Treinamento e avaliação.
- Artefatos necessários.
- Origem e licença dos dados.
- Resultados observados.
- Limitações.
- Papel de cada um dos três módulos exigidos pelo professor.

Prepare o repositório para revisão e futura publicação, sem incluir segredos, dependências instaladas ou arquivos temporários.

### 10. Preparar a apresentação

Crie um roteiro e conteúdo de slides com:

1. Problema.
2. Objetivo e escopo.
3. Interface, IA e resposta.
4. Dataset e prevenção de vazamento.
5. Modelos e baselines.
6. Resultados reais.
7. Demonstração.
8. Limitações e próximos passos.

Inclua exemplos reais de acerto e erro. Não escolha apenas casos favoráveis.

Explique a investigação do Q-Learning como parte da evolução do projeto, caso isso ajude a justificar a escolha final.

### Organização do trabalho

- **Dias 1–2:** preservação, auditoria, protocolo e primeiros modelos.
- **Dia 3:** avaliação, análise de erros e decisão de integração.
- **Dias 4–5:** integração e melhoria das respostas, se justificada.
- **Dia 6:** testes, documentação e organização da entrega.
- **Dia 7:** apresentação e ensaio.

Ao concluir cada etapa, informe brevemente:

- O que foi implementado.
- Quais verificações foram executadas.
- Quais resultados foram observados.
- Quais limitações permanecem.
- Qual decisão esses resultados sustentam.

**Comece inspecionando o projeto e preserve a versão atual antes de implementar a alternativa supervisionada.**