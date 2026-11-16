# SecureCode RL — documentação da implementação

Inventário e avaliação realizados em **16/11/2026**, com base no código, nos dados e nos artefatos presentes no workspace. A proposta de referência está em [plan.md](../plan.md). As evidências desta revisão estão em [verification.md](verification.md).

## 1. Objetivo e conclusão

O projeto investiga o uso de aprendizado por reforço para selecionar e sequenciar correções limitadas de vulnerabilidades em código Python. Implementa Q-Learning tabular, usa casos reais de um dataset público e compara a política aprendida com agentes aleatório e por regras.

**A aplicação funciona no ambiente verificado e atende à proposta de experimento acadêmico dentro do escopo documentado.** A API, a interface, as transformações e a inferência foram verificadas. As 54 avaliações salvas foram reproduzidas com os checkpoints existentes. Isso não demonstra um corretor geral de vulnerabilidades nem superioridade do Q-Learning: ele iguala a cobertura da baseline por regras, mas usa mais ações e obtém menor recompensa.

A validação certifica propriedades locais das alterações. Equivalência funcional do programa completo, regressões funcionais e segurança completa continuam sem comprovação.

## 2. Evolução e versões

| Entrega | Conteúdo |
|---|---|
| Experimento v1, em `experiments/v1/` | Snapshot de código, documentação, dados processados, métricas e checkpoints; 89 casos de três CWEs, com cinco casos SQL transformáveis |
| Experimento v2, na raiz | 454 casos de cinco CWEs; 45 transformáveis; sete ações; estado schema 2; validação cruzada por grupos |
| Versão declarada do software | `0.1.0` em `pyproject.toml`, `frontend/package.json` e na API |

“v2” identifica a evolução experimental e não uma release `2.0.0`. Esta revisão documentou e verificou a entrega local; não criou tag nem publicou release. O snapshot v1 é histórico e não foi revalidado nesta revisão.

## 3. Arquitetura e tecnologias

```text
Fontes OWASP + CSV oficial
          ↓ preparação, hashes e agrupamento
Dataset processado → análise AST → ambiente Gymnasium
                                       ↕
                              agente Q-Learning
                                       ↓
                       transformação → validação → recompensa

Checkpoints + métricas → FastAPI → proxy SvelteKit → navegador
```

O backend usa Python, FastAPI, Pydantic, NumPy, Gymnasium e Bandit. Os experimentos usam Pandas, Matplotlib e PyYAML. O frontend usa SvelteKit, TypeScript, Tailwind CSS e adapter-node. Pytest e HTTPX dão suporte aos testes. Há dependências fixadas em `requirements.txt`, um lock Python e `frontend/package-lock.json`.

Ambiente efetivamente verificado: **Python 3.11.15, Node 22.17.1 e npm 10.8.2**. Para comparar com os artefatos entregues, utilizar Python 3.11: versões posteriores podem analisar arquivos que esta versão rejeita e alterar as métricas.

## 4. Dados e rastreabilidade

O código de preparação fixa o OWASP Benchmark for Python 0.1 no commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. O corpus local registra 1.230 casos oficiais; 454 pertencem às categorias selecionadas.

Cada registro processado contém ID, categoria, CWE, rótulo original, indicador de vulnerabilidade, código, caminho da fonte, SHA-256, commit e grupo. Os rótulos vêm de `expectedresults-0.1.csv`. O carregamento verifica o hash do código; os testes comparam os registros com as fontes e os rótulos locais oficiais.

| CWE | Categoria | Casos | Positivos | Negativos | Transformáveis |
|---|---|---:|---:|---:|---:|
| 89 | SQL Injection | 16 | 5 | 11 | 5 |
| 78 | Command Injection | 20 | 13 | 7 | 0 |
| 94 | Code Injection | 53 | 20 | 33 | 0 |
| 614 | Cookie sem atributo Secure | 39 | 24 | 15 | 22 |
| 330 | Aleatoriedade inadequada | 326 | 99 | 227 | 18 |
| **Total** | | **454** | **161** | **293** | **45** |

O modelo demonstrativo usa 338 casos de treino, 63 de validação e 53 de teste. A avaliação principal usa 26 grupos heurísticos de fluxo AST, distribuídos em quatro folds. Em cada rodada, um fold é teste, o seguinte é validação e os outros dois são treino. Cada caso aparece no teste uma vez por semente, sem sobreposição de grupos entre partições da mesma rodada.

Os grupos não são identificadores oficiais de templates. O corpus já havia sido inspecionado; portanto, a validação cruzada é exploratória. Os 35 arquivos incompatíveis com Python 3.11 permanecem no corpus, reunidos em um grupo.

## 5. Componentes implementados

| Caminho | Responsabilidade |
|---|---|
| `backend/app/datasets/core.py` | Origem fixa, hashes, agrupamento AST e carregamento dos conjuntos |
| `backend/app/analysis/static.py` | Detecção de padrões AST e execução complementar do Bandit sobre texto |
| `backend/app/transformations/sql.py` | Transformação SQL restrita e rejeição de ações de Command/Code Injection |
| `backend/app/transformations/registry.py` | Registro das três correções, aplicabilidade e alterações textuais pontuais |
| `backend/app/validation/checks.py` | Comparação AST e certificação da propriedade local |
| `backend/app/environment/securecode.py` | Ambiente Gymnasium, estado, ações, recompensas e trajetória |
| `backend/app/agents/qlearning.py` | Q-Table, epsilon-greedy, Bellman, persistência e inferência |
| `backend/app/main.py` | API e carregamento da política selecionada |
| `backend/tests/` | Testes do núcleo, API, expansão, dados reais e partições |
| `frontend/src/routes/+page.svelte` | Analisador, editor, alertas, sequência de ações e comparação do código |
| `frontend/src/routes/dashboard/+page.svelte` | Resultados, seleção de semente/fold, gráficos e protocolo |
| `frontend/src/routes/api/v1/[...path]/+server.ts` | Proxy para rotas permitidas da API |
| `frontend/src/lib/` | Cliente HTTP, tipos TypeScript e gráficos |
| `frontend/src/style.css` e `+layout.svelte` | Aparência e navegação compartilhadas |
| `frontend/static/` | Exemplo OWASP e licença preservada |

### Análise e correções

O analisador identifica chamadas e padrões associados às cinco CWEs. Trata-se de detecção conservadora de pontos potencialmente perigosos, sem análise completa de fluxo de dados. Bandit complementa a resposta da API, mas não determina a recompensa do agente.

As correções disponíveis são:

1. **SQL:** substituir o padrão SQLite reconhecido por uma consulta com parâmetro vinculado, sem interpolar o valor na consulta.
2. **Cookie:** trocar `secure=False` por `True` no padrão restrito de resposta Flask reconhecido. Requer HTTPS e altera o envio do cookie em conexões HTTP.
3. **Aleatoriedade:** trocar `random.randbytes(32)` por `random.SystemRandom().randbytes(32)` em atribuições reconhecidas, preservando bytes e comprimento. Outros tamanhos e contratos são rejeitados.

As transformações preservam o texto ao redor das expressões alteradas. O validador compara a AST esperada com a AST resultante, rejeitando alterações adicionais. O certificado não comprova o protocolo completo de autenticação nem o comportamento integral do programa. Command Injection e Code Injection têm análise, mas nenhuma transformação automática implementada.

### Ambiente e aprendizado

O estado combina máscara dos alertas, contagem limitada, resultado da última ação, passos restantes, alteração pendente, status e máscara de aplicabilidade. ID, CWE oficial e rótulo não fazem parte da observação. Rótulos podem participar da recompensa e da avaliação.

| ID | Ação | Situação |
|---:|---|---|
| 0 | `FIX_SQL_INJECTION` | Implementada para o padrão restrito |
| 1 | `FIX_COMMAND_INJECTION` | Retorna incompatibilidade; sem correção |
| 2 | `FIX_CODE_INJECTION` | Retorna incompatibilidade; sem correção |
| 3 | `VALIDATE` | Verifica a alteração pendente |
| 4 | `STOP` | Encerra o episódio |
| 5 | `FIX_SECURE_COOKIE` | Implementada para o padrão restrito |
| 6 | `FIX_RANDOM_BYTES` | Implementada para o padrão restrito |

O orçamento padrão é de seis passos. A implementação atual representa 286.720 estados possíveis e sete ações. O agente usa atualização de Bellman, exploração epsilon-greedy e argmax determinístico na inferência; empates determinísticos escolhem o menor índice. Não há fallback por regras na política aprendida.

A configuração usa alpha 0,1, gamma 0,95, epsilon inicial 1, mínimo 0,05, decaimento 0,995 e 10.000 episódios por treinamento, com sementes 42, 43 e 44. A recompensa soma custo de ação −1, validação +10 e penalidades por incompatibilidade −5, alteração indevida −6 e encerramento com pendências −8. Existem parâmetros de regressão −12, preservação funcional +3 e conclusão +15; os bônus funcionais não são concedidos pelos validadores atuais, que não certificam equivalência funcional.

Os checkpoints NPZ são carregados com `allow_pickle=False`. A política demonstrativa é escolhida pela recompensa de validação, usando a menor semente como desempate, e fica em cache na API. Trocar checkpoints exige reiniciar a API.

## 6. API e interface

| Método e rota | Resultado |
|---|---|
| `GET /api/v1/health` | Disponibilidade e indicação de que código submetido não é executado |
| `GET /api/v1/dataset/info` | Manifesto de origem e partições |
| `GET /api/v1/dataset/distribution` | Cobertura das categorias |
| `POST /api/v1/analyze` | Sintaxe, alertas AST, Bandit e ressalva de interpretação |
| `POST /api/v1/repair` | Original, resultado, ações, status e validação |
| `GET /api/v1/model/info` | Metadados do checkpoint selecionado |
| `GET /api/v1/model/metrics` | Treinamento, curvas, holdout e validação cruzada |
| `GET /api/v1/experiments` | Resumo dos experimentos do holdout de teste |
| `GET /api/v1/experiments/{id}` | Experimento de teste com trajetórias |

Os POSTs recebem `{"code": "código Python"}`, entre 1 e 50.000 caracteres. Entrada inválida retorna 422; experimento inexistente, 404; artefatos ausentes ou política incompatível podem retornar 503. O health não verifica sozinho a disponibilidade do modelo ou das métricas.

Na página `/`, o usuário pode colar código ou carregar o exemplo oficial, analisar, pedir correções, consultar as ações e comparar original e resultado lado a lado. O editor é um textarea acessível; Monaco era opcional no plano. Os status distinguem proposta, propriedade local validada, alteração não verificada e ausência de correção suportada.

O dashboard `/dashboard` mostra dados reais dos artefatos, curvas de treinamento, baselines, categorias, ações, folds, sementes e hiperparâmetros. O proxy usa `BACKEND_URL`, com padrão `http://127.0.0.1:8000`, e limita as rotas encaminhadas. A aplicação é destinada ao uso local e não inclui autenticação ou quotas para exposição pública.

## 7. Scripts e artefatos entregues

| Script | Saída ou finalidade |
|---|---|
| `scripts/prepare_dataset.py` | Obtém/localiza o corpus fixado, verifica origem e gera dados e manifesto |
| `scripts/inspect_dataset.py` | Inspeciona categorias, sintaxe e cobertura de transformações |
| `scripts/prepare_folds.py` | Gera manifesto dos quatro folds |
| `training/train.py` | Treina três modelos demonstrativos e seleciona um por validação |
| `training/fit.py` | Rotina de treinamento usada na validação cruzada |
| `training/baselines.py` | Políticas aleatória e por regras |
| `training/evaluate.py` | Avalia os três agentes no holdout; gera JSON e CSV |
| `training/cross_validate.py` | Executa os 12 treinamentos e 36 avaliações da CV |
| `training/plots.py` | Gera gráficos e curvas |
| `scripts/report_results.py` | Gera o relatório de resultados |
| `scripts/smoke_web.py` | Testa integração HTTP e, opcionalmente, hidratação no Chrome |

`artifacts/checkpoints/` contém três modelos demonstrativos. `artifacts/cross_validation/` contém 12 checkpoints e seus históricos. `artifacts/metrics/` guarda treinamento, curvas, avaliações, trajetórias e tabelas; `artifacts/plots/` contém gráficos de recompensa, epsilon, correção, agentes, categorias, ações e CV. Os manifestos guardam origem, cobertura e partições.

`docs/feasibility.md` registra a inspeção inicial; `docs/expansion.md`, a ampliação e o protocolo; `docs/results.md`, os resultados; `docs/verification.md`, as verificações. `plan.md` preserva a proposta. Diretórios de ambiente, dependências, build e dados brutos/processados da raiz constam no `.gitignore`; uma instalação nova precisa preparar os dados conforme o README.

## 8. Resultados e atendimento à proposta

Resultados da CV, agregados sobre os casos fora do treino por semente:

| Política | Correções / tratáveis | Correções / positivos | Alterações indevidas | Recompensa média | Ações médias |
|---|---:|---:|---:|---:|---:|
| Q-Learning | 100% | 28,0% | 0% | −2,905 | 1,584 |
| Regras | 100% | 28,0% | 0% | −0,207 | 1,198 |
| Aleatória | 6,7% | 1,9% | 0% | −21,772 | 4,079 |

Q-Learning e regras validam 45 casos por semente. Dos 161 positivos, 116 não têm transformação suportada. Os 0% de alterações indevidas referem-se aos 293 negativos deste corpus, não a uma garantia para qualquer código. O relatório detalhado inclui detecção AST separada das métricas de correção.

| Critério da proposta | Avaliação da entrega |
|---|---|
| Dataset público, origem verificável e rótulos preservados | Atendido no corpus local; comparação com fontes e CSV passou |
| Ambiente Gymnasium funcional | Atendido pelos testes de contrato, orçamento e transições |
| Q-Learning implementado e treinado | Atendido; checkpoints funcionais e treinamento curto executado |
| Recompensa baseada em validação definida | Atendido para propriedades locais; funcionalidade completa permanece desconhecida |
| Comparação com baselines | Atendido com mesmas partições e orçamento |
| Resultados reproduzíveis | 54 avaliações reproduzidas exatamente com os checkpoints existentes |
| Interface com resultados reais | Atendido; API, proxy e dashboard verificados |
| Limitações documentadas | Atendido, incluindo cobertura, generalização e avaliação exploratória |
| Correção geral de Command/Code Injection | Não implementada; redução de escopo prevista e documentada |
| Superioridade da política aprendida | Não demonstrada; o plano pede investigação e relato fiel dos resultados |
| Sequenciamento complexo em dados reais | Evidência limitada; múltiplas correções são cobertas por teste controlado, não por um corpus real multivulnerabilidade |

Nos estados não visitados do grupo incompatível com Python 3.11, a política tabular pode repetir ações incompatíveis até consumir o orçamento. Isso contribui para o desempenho inferior em recompensa. A detecção de Command/Code Injection também tem falsos positivos relevantes. Essas limitações não impedem a demonstração acadêmica, mas restringem o alcance da conclusão.

## 9. Execução e reprodução

Na primeira instalação, seguir as dependências e a preparação descritas no [README](../README.md). Com o ambiente atual preparado, iniciar em terminais separados:

```bash
# Na raiz: API
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

```bash
# Em outro terminal: frontend
cd frontend
npm run dev
```

Abrir `http://127.0.0.1:5173` (ou a porta informada pelo Vite). A documentação interativa da API fica em `http://127.0.0.1:8000/docs`. Ambos os processos precisam permanecer ativos.

Para verificar a entrega:

```bash
.venv/bin/python -m pytest -q
cd frontend
npm run check
npm run build
cd ..
.venv/bin/python scripts/smoke_web.py --browser
```

O último comando requer Google Chrome; sem ele, omitir `--browser` mantém a verificação HTTP. O script abre portas locais temporárias e encerra seus servidores. O pipeline completo de preparação, treino e gráficos está no README e sobrescreve artefatos das mesmas sementes; arquivar os resultados antes de conduzir um novo experimento.

## 10. Alcance da revisão

Foram executados os 21 testes existentes, a checagem Svelte/TypeScript, um novo build, integração HTTP, hidratação do dashboard no Chrome, reprodução em memória das 54 avaliações e um treinamento curto de 30 episódios. As métricas de detecção e agregação da CV também foram conferidas.

Não foi repetido o treinamento integral de 150.000 episódios (30.000 demonstrativos e 120.000 de CV), nem realizada instalação limpa em outra máquina. A execução atual usa as dependências e os dados locais disponíveis. O smoke de navegador verifica a hidratação do dashboard; não automatiza todos os cliques do editor. A reprodução das avaliações não substitui uma avaliação externa independente.

Para uma entrega acadêmica, apresentar o projeto como **protótipo experimental de correção assistida com validação local** e incluir as métricas das baselines. Para ampliar sua aplicabilidade, ainda seriam necessários mais padrões de correção, dados externos, validação funcional e tratamento mais adequado de estados desconhecidos.
