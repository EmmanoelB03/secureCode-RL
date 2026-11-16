# Verificações da implementação

## Revisão executada em 16/11/2026

**Conclusão:** aplicação funcional no ambiente local verificado, adequada à proposta
de experimento acadêmico com correções restritas. A cobertura e o alcance científico
estão detalhados em [documentacao-projeto.md](documentacao-projeto.md).

Ambiente: Python 3.11.15, Node 22.17.1 e npm 10.8.2.

| Verificação | Resultado observado nesta revisão |
|---|---|
| `.venv/bin/python -m pytest -q` | **21 passaram**, em 1,41 s; um aviso de depreciação de `anyio.abc.BlockingPortal` no Starlette TestClient |
| `npm run check`, em `frontend/` | **Zero erros e zero avisos** |
| `npm run build`, em `frontend/` | Build de produção concluído com adapter-node |
| `.venv/bin/python scripts/smoke_web.py --browser` | Integração HTTP e hidratação do dashboard no Chrome aprovadas |
| Reprodução em memória das avaliações existentes | **54 avaliações idênticas** nas trajetórias e métricas: nove de validação, nove de teste demonstrativo e 36 de CV |
| Conferência dos dados experimentais | Hash do corpus no manifesto de folds, IDs de treino dos checkpoints de CV, detecção AST e métricas agregadas da CV conferidos |
| Treinamento curto com `training.fit.fit` | **30 episódios** com dados reais de treino, semente 42 e configuração atual; Q-Table atualizada e epsilon reduzido |

O teste HTTP confirmou respostas 200 para `/`, `/dashboard`,
`/api/v1/model/metrics` e `/api/v1/experiments`. Também confirmou análise e correção
do exemplo oficial por POST através do proxy SvelteKit. No Chrome, verificou
o dashboard hidratado, com validação cruzada e 454 exemplos carregados da API.

A reprodução adicional foi executada por um bloco Python temporário, sem adicionar
um novo comando ao projeto: carregou cada checkpoint NPZ, reconstruiu o agente
correspondente (Q-Learning, regras ou aleatório), executou `training.evaluate.rollout`
sobre a partição registrada e comparou a lista completa de episódios e
`summarize(...)` com os JSONs salvos. Para a política aleatória da CV, preservou
a semente `seed + 1000 * fold`. Recalculou também `detection(all_rows)` e as nove
agregações por política/semente. Todas as comparações passaram.

O treinamento curto usou uma cópia da configuração com `episodes=30`; os checkpoints,
históricos e métricas entregues não foram sobrescritos por essa conferência.
O build do frontend foi regenerado. Não foi repetido o treinamento integral,
nem feita instalação limpa em outra máquina. A revisão histórica abaixo continua
separada das evidências atuais.

O sandbox bloqueou a abertura de porta local (`listen EPERM`) e a execução inicial
da suíte ficou bloqueada na comunicação do TestClient. Após autorização, suíte e
smoke foram executados fora dessa restrição e passaram. A execução inicial foi
interrompida; os servidores temporários do smoke foram encerrados pelo script.

## Registro anterior da implementação v2

- Python 3.11.15, versão 2: **21 testes passaram** (`python -m pytest -q`).
- Cobertura: 45 transformações reais validadas; originais e rótulos comparados ao CSV/fonte OWASP.
- Quatro folds verificados sem grupos compartilhados entre partições; cada ID no teste uma vez por semente.
- Testes adicionais cobrem cookies Secure, bytes do SO, rejeição de contratos diferentes e duas correções sequenciais.
- O teste `check_env` do Gymnasium confirmou o contrato de reset/step/espaços.
- Casos reais de treino verificaram transformação SQL, rejeição e preservação de negativos.
- Testes controlados de SQLite verificaram binding e preservação de consultas benignas.
- Testes cobrem Bellman terminal/não terminal, checkpoints, orçamento, penalidades,
  ausência de rótulo no estado, validação sem recompensa repetida e código não executado.
- API testada com validação de entrada e artefatos reais, incluindo a política treinada.
- Svelte/TypeScript: **zero erros e zero avisos** (`npm run check`).
- Build SvelteKit com adapter-node concluído (`npm run build`).
- Integração HTTP real: páginas `/` e `/dashboard`, métricas e experimentos retornaram 200.
- POST de análise e correção pelo proxy SvelteKit validado com exemplo oficial.
- Google Chrome headless carregou e hidratou o dashboard v2 com validação cruzada e 454 exemplos da API.

Os testes HTTP precisaram executar fora da restrição de rede do sandbox: a abertura
de portas locais e a comunicação interna do TestClient estavam bloqueadas.
Os servidores temporários foram encerrados pelo script de smoke test.

Isso não equivale a auditoria de segurança nem a validação funcional do benchmark.
Não foram executados a aplicação OWASP, seus módulos auxiliares ou código submetido.
