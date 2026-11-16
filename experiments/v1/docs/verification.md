# Verificações da implementação

- Python 3.11.15: **11 testes passaram** (`python -m pytest -q`).
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
- Google Chrome headless carregou e hidratou o dashboard com resultados da API.

Os testes HTTP precisaram executar fora da restrição de rede do sandbox: a abertura
de portas locais e a comunicação interna do TestClient estavam bloqueadas.
Os servidores temporários foram encerrados pelo script de smoke test.

Isso não equivale a auditoria de segurança nem a validação funcional do benchmark.
Não foram executados a aplicação OWASP, seus módulos auxiliares ou código submetido.
