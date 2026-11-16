# SecureCode RL — Plano de Implementação v2

## 1. Visão geral

Desenvolver um sistema inteligente de análise e correção assistida de vulnerabilidades em código Python utilizando **Q-Learning**, com treinamento fundamentado em um dataset público existente.

O projeto deverá investigar se um agente de aprendizado por reforço consegue aprender uma política eficiente de seleção e sequenciamento de correções de segurança.

### Requisito acadêmico obrigatório

O treinamento e a avaliação deverão utilizar exemplos provenientes de um dataset público, verificável e academicamente reconhecido.

Não será permitido substituir o dataset por exemplos inteiramente sintéticos criados durante a implementação.

Exemplos artificiais poderão ser utilizados exclusivamente em testes unitários do software, não como substitutos dos dados de treinamento ou dos resultados experimentais.

## 2. Dataset oficial

**Nome:** OWASP Benchmark for Python

**Repositório:** https://github.com/OWASP-Benchmark/BenchmarkPython

**Organização:** OWASP Benchmark Project

**Versão inicial:** 0.1

**Quantidade documentada:** 1.230 casos de teste.

O dataset contém código Python deliberadamente vulnerável e casos negativos, com classificação por CWE.

Utilizar:

- Código-fonte original dos casos de teste.
- Identificadores oficiais de cada caso.
- Categoria CWE.
- Rótulo esperado de vulnerabilidade.
- Metadados disponíveis no repositório.

O arquivo `expectedresults-0.1.csv` será utilizado como fonte dos rótulos oficiais.

### Reprodutibilidade

Criar um script:

```bash
python scripts/prepare_dataset.py
```

Esse script deverá:

1. Baixar ou localizar o repositório oficial.
2. Registrar a URL e o commit Git utilizado.
3. Verificar a existência dos arquivos de código e rótulos.
4. Ler os casos de teste e seus metadados.
5. Associar cada exemplo ao rótulo oficial.
6. Filtrar as categorias suportadas.
7. Gerar registros padronizados para o ambiente.
8. Separar treinamento, validação e teste.
9. Produzir um relatório das quantidades e distribuições.

Não alterar os rótulos originais.

Não criar exemplos extras para completar artificialmente uma quantidade mínima.

Preservar referências para os arquivos originais e o identificador de cada caso.

## 3. Escolha das vulnerabilidades

Inicialmente, investigar estas categorias:

| Categoria | CWE | OWASP Top 10:2025 |
|---|---|---|
| SQL Injection | CWE-89 | A05 — Injection |
| Command Injection | CWE-78 | A05 — Injection |
| Code Injection | CWE-94 | A05 — Injection |

Essas categorias pertencem à mesma área geral de risco, mas exigem mecanismos de correção distintos.

Antes de implementar as correções, inspecionar os exemplos reais e verificar:

- Quantos são vulneráveis.
- Quantos são casos negativos.
- Quantos permitem uma transformação automática segura.
- Quais dependem de contexto externo.
- Quais possuem dependências ou comportamentos difíceis de validar.

**Não assumir que todas as categorias poderão ser corrigidas automaticamente.**

Se a quantidade de exemplos aproveitáveis for insuficiente, avaliar a inclusão de Path Traversal (CWE-22) ou outras categorias presentes no próprio dataset.

Registrar qualquer alteração de escopo no relatório.

## 4. Arquitetura

### Stack

Backend:
- Python 3.11+
- FastAPI
- Pydantic
- NumPy
- Gymnasium
- Python AST
- Bandit
- Pytest

Frontend:
- SvelteKit
- TypeScript
- Tailwind CSS
- Monaco Editor, se a integração for viável

Experimentos:
- Pandas
- Matplotlib
- CSV/JSON
- Checkpoints de Q-Table

### Fluxo

```text
OWASP Benchmark Python
        |
        v
Dataset Loader
        |
        v
Análise estática e extração
de características
        |
        v
Ambiente Gymnasium
        |
        v
Agente Q-Learning
        |
        v
Seleção de correções
        |
        v
Validação controlada
        |
        v
Recompensa
        |
        v
Atualização da Q-Table
```

O agente não deverá acessar os rótulos oficiais como parte do estado.

Os rótulos serão utilizados pelo ambiente de treinamento e pelo sistema de avaliação.

## 5. Ambiente de aprendizado por reforço

Implementar:

```python
class SecureCodeEnv(gym.Env):
    ...
```

### Estados

O estado deverá representar características observáveis, como:

- Tipos de alertas detectados.
- Quantidade de alertas restantes.
- Resultado da última ação.
- Quantidade de ações restantes.
- Se existem modificações aguardando validação.
- Status de validação do código atual.

Representar essas características em um espaço discreto e limitado.

Não utilizar o identificador do exemplo ou seu rótulo oficial como estado, evitando que o agente simplesmente memorize o dataset.

### Ações

Definir inicialmente:

```python
ACTIONS = {
    0: "FIX_SQL_INJECTION",
    1: "FIX_COMMAND_INJECTION",
    2: "FIX_CODE_INJECTION",
    3: "VALIDATE",
    4: "STOP"
}
```

Cada ação de correção deverá corresponder a uma transformação explícita, testável e documentada.

As transformações não deverão executar código recebido do usuário.

Quando uma correção não for aplicável, retornar um resultado estruturado indicando incompatibilidade.

### Natureza sequencial

Permitir múltiplas ações por episódio.

O ambiente deverá lidar com situações em que:

- Uma correção resolve um problema.
- Uma correção não se aplica.
- Uma correção introduz regressões.
- Mais de uma ação é necessária.
- O agente deve decidir parar.
- Nenhuma correção automática é segura.

A política não deverá depender de decisões codificadas diretamente em `if/else`.

## 6. Sistema de recompensas

Definir uma função de recompensa parametrizável.

Proposta inicial:

| Evento | Recompensa |
|---|---:|
| Correção validada | +10 |
| Todas as falhas tratáveis corrigidas | +15 |
| Testes funcionais preservados | +3 |
| Ação incompatível | -5 |
| Regressão funcional | -12 |
| Alteração desnecessária | -6 |
| Encerrar com falhas tratáveis pendentes | -8 |
| Custo de cada ação | -1 |

Esses valores são hiperparâmetros iniciais, não resultados experimentais.

### Validação das correções

O rótulo oficial do OWASP Benchmark informa a presença esperada da vulnerabilidade, mas não comprova que uma transformação aplicada pelo agente corrigiu o problema.

Portanto, desenvolver validadores específicos para as categorias suportadas.

Usar, quando aplicável:

- Análise AST.
- Análise estática com Bandit ou regras específicas.
- Verificação sintática.
- Testes de regressão controlados.
- Propriedades de segurança definidas para cada transformação.

Caso não seja possível determinar se uma correção é válida, classificar o resultado como não verificado.

Não conceder recompensa máxima por correções não verificadas.

## 7. Algoritmo Q-Learning

Implementar o algoritmo tabular sem utilizar uma biblioteca que já forneça a política pronta.

Parâmetros iniciais:

```python
ALPHA = 0.1
GAMMA = 0.95
EPSILON_START = 1.0
EPSILON_MIN = 0.05
EPSILON_DECAY = 0.995
EPISODES = 10000
SEED = 42
```

Implementar:

- Q-Table.
- Estratégia epsilon-greedy.
- Atualização de Bellman.
- Decaimento de epsilon.
- Salvamento de checkpoints.
- Carregamento da política treinada.
- Inferência determinística.
- Histórico de recompensas.

O número de episódios representa interações com o ambiente, não a quantidade de códigos distintos no dataset.

Permitir múltiplas sementes para avaliação da estabilidade do aprendizado.

## 8. Divisão do dataset

Criar três conjuntos:

- Treinamento: aproximadamente 70%.
- Validação: aproximadamente 15%.
- Teste: aproximadamente 15%.

Essas proporções são metas, não números rígidos.

Manter a distribuição de categorias quando possível.

Evitar que casos quase idênticos ou variantes geradas a partir do mesmo template apareçam em partições diferentes.

Preservar os casos negativos para avaliar alterações indevidas.

Se não for possível criar divisões confiáveis para alguma categoria devido à pequena quantidade de exemplos, documentar a limitação e utilizar um protocolo de avaliação apropriado.

O conjunto de teste não poderá ser utilizado para ajustar hiperparâmetros, transformações ou recompensas.

## 9. Baselines e avaliação

Comparar três políticas:

**Random Agent**

Escolhe ações aleatoriamente.

**Rule-Based Agent**

Aplica uma política determinística de seleção de transformações.

**Q-Learning Agent**

Utiliza a política aprendida durante o treinamento.

Executar os três agentes sobre os mesmos exemplos.

### Métricas principais

- Taxa de correções validadas.
- Taxa de alterações indevidas.
- Percentual de regressões funcionais.
- Quantidade média de ações por episódio.
- Recompensa média.
- Taxa de conclusão bem-sucedida.
- Quantidade de casos não suportados.

### Métricas de detecção

Quando avaliando o analisador estático separadamente, utilizar:

- Precision.
- Recall.
- F1-score.
- False Positive Rate.
- False Negative Rate.

Não confundir métricas de detecção de vulnerabilidades com métricas de sucesso da política de correção.

### Gráficos

Gerar:

1. Recompensa média por episódio.
2. Evolução de epsilon.
3. Taxa de correção durante o treinamento.
4. Comparação dos três agentes.
5. Resultados por categoria CWE.
6. Distribuição de ações escolhidas.

Relatar os resultados observados, mesmo quando o Q-Learning não superar as baselines.

## 10. Interface web

Criar uma aplicação com duas páginas.

### Página 1 — Analisador de código

Funcionalidades:

- Editor Python.
- Botão para analisar.
- Lista de possíveis vulnerabilidades.
- Identificação de CWE e categoria OWASP.
- Botão para sugerir correções.
- Visualização das ações escolhidas pelo agente.
- Comparação de código original e corrigido.
- Status de validação das alterações.

Diferenciar visualmente:

- Vulnerabilidade detectada.
- Correção proposta.
- Correção validada.
- Correção não verificada.
- Caso não suportado.

O sistema não deverá afirmar que um código está completamente seguro apenas porque os alertas conhecidos desapareceram.

### Página 2 — Dashboard do treinamento

Apresentar:

- Dataset utilizado.
- Versão e origem dos dados.
- Quantidade de exemplos.
- Distribuição de CWEs.
- Episódios de treinamento.
- Recompensas.
- Taxa de correções.
- Comparação de baselines.
- Configuração dos hiperparâmetros.

Os gráficos deverão ser gerados a partir de resultados reais.

## 11. Backend FastAPI

Implementar os endpoints:

```text
GET  /api/v1/health

GET  /api/v1/dataset/info
GET  /api/v1/dataset/distribution

POST /api/v1/analyze
POST /api/v1/repair

GET  /api/v1/model/info
GET  /api/v1/model/metrics

GET  /api/v1/experiments
GET  /api/v1/experiments/{id}
```

O treinamento deverá acontecer por script independente, fora da API.

A API deverá carregar uma política previamente treinada.

Não permitir execução arbitrária do código enviado pelo usuário.

## 12. Segurança operacional

Todos os arquivos de código do dataset deverão ser tratados como conteúdo não confiável.

A aplicação poderá realizar leitura, parsing e análise estática sem executar esses arquivos.

Testes que necessitem de execução deverão ocorrer em ambiente rigorosamente isolado, com recursos limitados, sem acesso à rede ou a dados sensíveis.

Não iniciar aplicações deliberadamente vulneráveis em interfaces públicas.

Não executar payloads provenientes de fontes desconhecidas na máquina principal.

O frontend e o backend não deverão ter funcionalidades de execução arbitrária de código.

## 13. Estrutura do repositório

```text
securecode-rl/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── agents/
│   │   ├── analysis/
│   │   ├── environment/
│   │   ├── transformations/
│   │   ├── validation/
│   │   ├── datasets/
│   │   ├── services/
│   │   └── main.py
│   └── tests/
│
├── frontend/
│   └── src/
│
├── training/
│   ├── train.py
│   ├── evaluate.py
│   ├── baselines.py
│   └── config.yaml
│
├── scripts/
│   ├── prepare_dataset.py
│   └── inspect_dataset.py
│
├── datasets/
│   ├── raw/
│   ├── processed/
│   └── manifests/
│
├── artifacts/
│   ├── checkpoints/
│   ├── metrics/
│   └── plots/
│
├── docs/
├── README.md
└── .gitignore
```

## 14. Fases de implementação

### Fase 1 — Inspeção do dataset

Esta fase é obrigatória antes de implementar a IA.

1. Baixar o OWASP Benchmark Python.
2. Inspecionar os arquivos e rótulos.
3. Listar CWEs e suas quantidades.
4. Identificar os casos positivos e negativos.
5. Verificar quais vulnerabilidades admitem correção controlada.
6. Produzir um relatório de viabilidade.

**Entregável:** dataset oficial preparado, manifesto de origem e relatório de cobertura.

### Fase 2 — Analisador estático

Implementar o analisador AST e integrar Bandit.

Criar testes utilizando exemplos reais selecionados da OWASP.

**Entregável:** módulo capaz de identificar padrões suportados sem executar o código.

### Fase 3 — Transformações

Implementar transformações seguras e limitadas.

Validar as transformações em exemplos do dataset.

Rejeitar explicitamente casos incompatíveis.

**Entregável:** mecanismo de correção com status de sucesso, falha ou incompatibilidade.

### Fase 4 — Ambiente Gymnasium

Implementar estados, ações, recompensas e condições de término.

Utilizar exclusivamente exemplos do dataset preparado para os experimentos.

**Entregável:** ambiente de RL funcional e testado.

### Fase 5 — Treinamento

Implementar Q-Learning, checkpoints, métricas e gráficos.

Executar múltiplas sementes.

**Entregável:** política treinada e histórico reprodutível.

### Fase 6 — Experimentos

Comparar Random Agent, Rule-Based Agent e Q-Learning.

Registrar resultados em exemplos não vistos.

**Entregável:** tabela de métricas e gráficos comparativos.

### Fase 7 — Aplicação web

Criar backend FastAPI e frontend SvelteKit.

Integrar a política treinada e os resultados de avaliação.

**Entregável:** aplicação funcional e demonstrável.

## 15. Critérios de aceitação final

O projeto estará concluído quando:

- O dataset oficial for obtido e documentado.
- Os rótulos originais forem preservados.
- A origem de cada exemplo utilizado for rastreável.
- O ambiente Gymnasium funcionar corretamente.
- O Q-Learning for implementado e treinado.
- As recompensas vierem de resultados de validação definidos.
- Houver comparação com baselines.
- Os experimentos forem reproduzíveis.
- A interface apresentar resultados reais.
- As limitações estiverem documentadas.

## 16. Instruções finais ao Codex

Implementar o projeto de forma incremental, começando obrigatoriamente pela inspeção do OWASP Benchmark for Python.

Não criar um dataset sintético para substituir a fonte oficial.

Antes do treinamento, apresentar as quantidades reais de exemplos utilizáveis em cada CWE e verificar se existe suporte suficiente para as ações propostas.

Se alguma transformação não for viável, ajustar o escopo de forma documentada, sem falsificar exemplos, rótulos ou resultados.

Priorizar o funcionamento do ambiente e do Q-Learning antes da implementação do frontend.

O objetivo é produzir um experimento acadêmico verificável sobre a aplicação de aprendizado por reforço à correção assistida de vulnerabilidades, fundamentado em dados públicos existentes.

**Comece pela Fase 1 e registre as evidências de origem e adequação do dataset antes de avançar.**
