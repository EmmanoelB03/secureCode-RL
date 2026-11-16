# SecureCode RL

Experimento local de correção assistida de código Python com Q-Learning tabular,
FastAPI e SvelteKit. Usa **454 casos reais** das categorias CWE-89, CWE-78, CWE-94, CWE-614 e CWE-330
do OWASP Benchmark Python 0.1, que contém 1.230 casos no total.

A versão 2 amplia de **5 para 45 casos transformáveis**: 5 SQL, 22 cookies sem
Secure e 18 geradores de bytes aleatórios. Command Injection e Code Injection
permanecem como casos de análise e abstenção. A validação comprova somente a
propriedade local modificada; equivalência funcional completa não é alegada.
Cookies Secure exigem HTTPS. Os resultados anteriores estão em `experiments/v1/`.

A avaliação principal usa **validação cruzada por grupos, com 4 folds e 3 sementes**.
Cada exemplo é testado uma vez por semente, sempre fora do treino da rodada.
O protocolo e as restrições estão em [docs/expansion.md](docs/expansion.md).

## Documentação da entrega

O inventário dos componentes, arquitetura, API, dados, treinamento, resultados e
atendimento à proposta está em [Documentação do projeto](docs/documentacao-projeto.md).
A [verificação de 16/11/2026](docs/verification.md) registra os testes executados e
seus limites: aplicação funcional no escopo experimental, com correções locais
para 45 casos e sem vantagem demonstrada sobre a baseline por regras.

## Iniciar

Reprodução de referência: Python **3.11.15**, Node **22.17.1**, npm 10.8.2.
Python 3.12+ pode analisar arquivos incompatíveis com 3.11 e mudar os resultados;
utilize 3.11 para reproduzir os artefatos entregues.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock.txt
python scripts/prepare_dataset.py
python scripts/inspect_dataset.py
```

Os checkpoints e resultados já estão em `artifacts/`; não é necessário treinar
novamente para usar a aplicação. **A API e o frontend precisam ficar ativos em
dois terminais separados. `npm run dev` inicia somente o frontend.**

**Terminal 1 — API:** execute na raiz do projeto e mantenha o terminal aberto:

```bash
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — frontend:** partindo da raiz do projeto, execute e mantenha aberto:

```bash
cd frontend
npm ci # Na primeira instalação ou quando o package-lock.json mudar
npm run dev
```

Abra **http://127.0.0.1:5173**. Documentação da API: http://127.0.0.1:8000/docs.
A interface tem analisador/editor Python, exemplo oficial, alertas AST/Bandit,
sequência do agente, comparação de código e dashboard com resultados reais.
O editor utiliza textarea acessível; Monaco foi dispensado nesta versão.

Fechar um desses terminais ou pressionar `Ctrl+C` encerra o respectivo servidor.
Nas próximas sessões, inicie novamente os dois servidores; não é necessário
reinstalar as dependências ou preparar o dataset a cada uso.

### Erro: “Backend indisponível. Inicie a API na porta 8000.”

Essa mensagem indica que o frontend não conseguiu obter uma resposta da API.
Verifique primeiro se o servidor do **Terminal 1** está ativo. Se estiver parado,
execute na raiz do projeto:

```bash
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Em outro terminal, confirme a conexão direta e a conexão pelo frontend:

```bash
curl http://127.0.0.1:8000/api/v1/health
curl http://127.0.0.1:5173/api/v1/health
```

Ambas devem retornar `{"status":"ok","executes_submitted_code":false}`.
Se o Vite indicar outra porta para o frontend, use essa porta no segundo comando.
Depois, tente **Analisar código** novamente na interface.

Se a API responder diretamente, mas falhar pelo frontend, verifique `BACKEND_URL`
no ambiente do frontend: o padrão é `http://127.0.0.1:8000`. Reinicie o frontend
após corrigir essa configuração. Se a API encerrar com erro, consulte a mensagem
no Terminal 1 para identificar a causa.

## Reproduzir o experimento

```bash
source .venv/bin/activate
python scripts/prepare_dataset.py
python scripts/inspect_dataset.py
python scripts/prepare_folds.py
python training/cross_validate.py
python training/train.py
python training/evaluate.py --split validation
python training/evaluate.py --split test
python training/plots.py
python scripts/report_results.py
python -m pytest -q
cd frontend
npm run check
npm run build
```

Validação cruzada: 12 treinamentos (4 folds × 3 sementes), com 10.000 episódios
cada; os testes têm 96–141 exemplos e 9–13 tratáveis por fold. Os hiperparâmetros
foram mantidos, sem ajuste pelos resultados externos.

Modelo demonstrativo: 10.000 episódios por semente (42, 43, 44), 338 códigos de
treino, 63 de validação e 53 de teste. Essa separação é secundária e não substitui a CV. A escolha do checkpoint usa somente recompensa na validação, com menor
semente como desempate. O teste não é lido pelo treinamento. Reinicie a API depois
de substituir checkpoints: a política é carregada sob demanda e mantida em cache.

Os scripts de treinamento sobrescrevem artefatos das mesmas sementes. Para
comparações com configurações novas, arquive primeiro `artifacts/`. Não ajuste
transformações ou hiperparâmetros para melhorar os resultados deste holdout.

Teste HTTP da aplicação compilada (execute na raiz, com o ambiente virtual ativo):

```bash
python scripts/smoke_web.py
# Opcional, com Google Chrome instalado:
python scripts/smoke_web.py --browser
```

O teste abre somente portas locais temporárias e encerra os servidores ao terminar.

## Arquitetura

```text
CSV + fontes oficiais → preparação + agrupamento → AST → Gymnasium
                                                     ↓
                    Q-Table ← recompensa ← validação ← transformação

Checkpoint + métricas → FastAPI ← proxy SvelteKit ← navegador
```

- `backend/app/analysis`: regras conservadoras de sinks e integração Bandit.
- `backend/app/transformations`: SQLite, Secure de cookie e SystemRandom para 32 bytes; preserva texto e licença.
- `backend/app/validation`: comparação AST e certificado de propriedade local.
- `backend/app/environment`: sete ações, episódios com até seis passos e recompensas configuráveis.
- `backend/app/agents`: epsilon-greedy, atualização de Bellman e checkpoints NPZ sem pickle.
- `training`: treinamento, baselines, avaliação, CSV/JSON e gráficos PNG de treino, holdout e CV.
- `datasets/manifests`: origem, hashes, IDs, partições e cobertura.
- `docs/feasibility.md`: inspeção histórica v1.
- `docs/expansion.md`: inspeção v2, novas propriedades e protocolo de CV.
- `docs/results.md`: resultados observados e interpretação.

O estado discreto contém máscara dos alertas, contagem limitada, último resultado,
passos disponíveis, validação pendente, status e máscara de aplicabilidade das três transformações. O schema 2 é
incompatível com checkpoints v1; os checkpoints atuais foram retreinados.
Não contém ID, CWE oficial nem rótulo. O agente aprendido seleciona ações por
argmax da Q-Table, sem política de reparo codificada por regras.

## Métricas e limitações

Correção validada / positivos inclui casos sem transformação suportada. Correção /
tratáveis usa somente positivos com transformação disponível. Alterações indevidas
usa negativos oficiais como denominador. Regressão funcional e sucesso completo
são desconhecidos (`null`), não zero. Detecção AST é medida separadamente; Bandit
é uma análise complementar da API, não o oracle de recompensa.

Os grupos são uma heurística AST de famílias de fluxo, não IDs de template oficiais.
A CV usa 454 casos, com 45 tratáveis; há somente quatro grupos de SQL positivo.
O corpus já foi inspecionado: a CV é exploratória e não constitui confirmação
independente. O Q-Learning validou os 45 tratáveis em cada semente, mas não superou
a baseline por regras em recompensa. Consulte [docs/results.md](docs/results.md).

Não há execução de código submetido nem importação de módulos do dataset.
Testes SQLite usam somente um harness confiável em memória. Não inicie `app.py`
do benchmark nem instale suas dependências para executar este projeto.
A aplicação entregue destina-se ao uso local; não inclui autenticação ou quotas
para exposição pública.

## Build local

```bash
cd frontend
npm run build
HOST=127.0.0.1 PORT=3000 ORIGIN=http://127.0.0.1:3000 node build
```

`BACKEND_URL` permite configurar a origem privada do backend; padrão
`http://127.0.0.1:8000`. O proxy aceita somente os endpoints previstos, sem CORS aberto.

## Fonte e atribuição

Dataset: https://github.com/OWASP-Benchmark/BenchmarkPython, commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. O exemplo em
`frontend/static/example.py` é uma cópia inalterada de `BenchmarkTest00099.py`,
com seu cabeçalho original. A licença GPL-3.0 do benchmark foi preservada em
`frontend/static/OWASP-LICENSE.txt`; os arquivos brutos conservam a licença original.
Mapeamento OWASP: https://top10.owasp.org/2025/A05_2025-Injection/.
