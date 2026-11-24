<script lang="ts">
  import { api, type Analysis, type Repair } from '$lib/api';
  let code = $state('');
  let analysis = $state<Analysis | null>(null);
  let repair = $state<Repair | null>(null);
  let busy = $state('');
  let error = $state('');
  const labels: Record<string,string> = { validated: 'Propriedade local validada', proposed: 'Correção proposta', unverified: 'Correção não verificada', partial: 'Correção parcial — revise os itens restantes', unsupported: 'Nenhuma correção automática aplicável' };
  type Line = { text: string; kind: 'same' | 'del' | 'add' };
  function diffLines(a: string, b: string): { left: Line[]; right: Line[] } {
    const x = a.split('\n'), y = b.split('\n');
    const n = x.length, m = y.length;
    const lcs = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--)
      lcs[i][j] = x[i] === y[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    const left: Line[] = [], right: Line[] = [];
    let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && x[i] === y[j]) { left.push({ text: x[i++], kind: 'same' }); right.push({ text: y[j++], kind: 'same' }); }
      else if (j < m && (i >= n || lcs[i][j + 1] >= lcs[i + 1][j])) right.push({ text: y[j++], kind: 'add' });
      else left.push({ text: x[i++], kind: 'del' });
    }
    return { left, right };
  }
  let diff = $derived(repair && repair.changed ? diffLines(repair.original, repair.modified) : null);
  function edited() { analysis = null; repair = null; error = ''; }
  async function sample() {
    busy = 'sample'; error = '';
    try { const r = await fetch('/example.py'); if (!r.ok) throw new Error('Exemplo indisponível'); code = await r.text(); edited(); }
    catch(e) { error = String(e); } finally { busy = ''; }
  }
  async function run(kind: 'analyze' | 'repair') {
    busy = kind; error = '';
    try {
      if (kind === 'analyze') { analysis = await api<Analysis>(kind, code); repair = null; }
      else repair = await api<Repair>(kind, code);
    } catch(e) { error = e instanceof Error ? e.message : String(e); } finally { busy = ''; }
  }
</script>
<section class="intro"><div><p class="eyebrow">01 / ANÁLISE ASSISTIDA</p><h1>Entenda o risco.<br/><span>Revise a correção.</span></h1><p class="lead">Classifique código Python, examine indícios estáticos e revise correções restritas. Modelos treinados em exemplos públicos da OWASP.</p></div><aside class="scope"><span class="dot"></span> Análise estática<p>O código enviado é tratado como texto.<br/>Correções automáticas têm escopo limitado.</p><a href="/dashboard">Explorar os resultados reais ↗</a></aside></section>
<div class="workspace">
  <section class="panel editor-panel"><div class="panel-heading"><h2>Código de entrada</h2><span class="mono">PYTHON</span></div>
    <div class="editor-toolbar"><span>{code.split('\n').length} linhas</span><button class="text-button" onclick={sample} disabled={!!busy}>Carregar exemplo OWASP ↙</button></div>
    <label class="sr-only" for="python">Código Python</label><textarea id="python" bind:value={code} oninput={edited} disabled={!!busy} spellcheck="false" maxlength="50000" placeholder="# Cole seu código Python aqui…" aria-describedby="code-note"></textarea>
    <div class="editor-bottom"><span id="code-note">{code.length.toLocaleString('pt-BR')} / 50.000 caracteres</span><div class="flex flex-wrap gap-3"><button class="secondary" onclick={() => run('analyze')} disabled={!!busy || !code.trim()}>{busy === 'analyze' ? 'Analisando…' : 'Analisar código'}</button><button class="primary" onclick={() => run('repair')} disabled={!!busy || !code.trim()}>{busy === 'repair' ? 'Consultando política…' : 'Sugerir correções →'}</button></div></div>
  </section>
  <section class="panel findings" aria-live="polite"><div class="panel-heading"><h2>Diagnóstico</h2><span class="badge">AST + Bandit</span></div>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    {#if !analysis && !repair}<div class="empty-state"><div class="empty-icon">⌕</div><h3>Comece com uma análise</h3><p>Os alertas, suas categorias e as decisões do agente aparecerão aqui.</p></div>{/if}
    {#if analysis}
      {#if analysis.classification}<article class="finding"><h3>Classificação por IA</h3><p>{analysis.classification.label}</p><small>{analysis.classification.model || ""} · {analysis.classification.version || ""}</small><p class="notice">{analysis.classification.notice || ""}</p>{#if analysis.classification.status === "completed" && analysis.syntax_valid && analysis.classification.positive !== !!analysis.alerts.length}<p class="notice">O classificador e as regras AST divergem. Revise os indícios abaixo.</p>{/if}</article>{/if}
      <h3>Indícios das regras AST</h3>
      {#if !analysis.syntax_valid}<p class="error">Sintaxe incompatível: {analysis.error}</p>{/if}
      {#each analysis.alerts as alert}<article class="finding"><div class="flex justify-between gap-2"><span class="status detected">Possível vulnerabilidade</span><span class="mono">L{alert.line}</span></div><h3>CWE-{alert.cwe} <span> / {alert.sink}</span></h3><p>{alert.owasp}</p><small>{alert.message}</small></article>{/each}
      {#if analysis.syntax_valid && !analysis.alerts.length}<p class="notice">Nenhum padrão conhecido foi detectado pelas regras AST.</p>{/if}
      <details><summary>Bandit · {analysis.bandit.results.length} alertas ({analysis.bandit.status})</summary>{#each analysis.bandit.results as finding}<p class="bandit-item">L{finding.line_number} · {finding.test_id} — {finding.issue_text}</p>{/each}</details>
      <p class="notice">{analysis.notice}</p>
    {/if}
    {#if repair}<div class="repair-result"><span class="status {repair.status}">{labels[repair.status] || repair.status}</span><h3>Ações do agente (Q-Learning) e das regras gerais</h3><ol class="trace">{#each repair.actions as action, i}<li><span>{String(i+1).padStart(2,'0')}</span><div><strong>{action.action}</strong><small>{action.source || 'Q-Learning'} · {action.outcome}</small>{#if action.detail}<small>{action.detail}</small>{/if}</div></li>{/each}</ol>{#if repair.unfixed?.length}<h3>Não corrigido automaticamente</h3>{#each repair.unfixed as item}<article class="finding"><div class="flex justify-between gap-2"><span class="status detected">CWE-{item.cwe}</span><span class="mono">L{item.line}</span></div><small>{item.reason}</small></article>{/each}{/if}{#if repair.alerts?.length}<p class="notice">Alertas restantes após a correção: {repair.alerts.map(a => `CWE-${a.cwe} (L${a.line})`).join(', ')}</p>{/if}<p class="notice">{repair.notice}</p></div>{/if}
  </section>
</div>
{#if repair && !repair.changed}<section class="panel diff"><div class="panel-heading"><h2>Revisão das alterações</h2><span class="badge">Sem alterações</span></div><p class="notice">O código não foi modificado: nenhuma correção automática segura se aplica a ele. Veja ao lado os motivos e os alertas que exigem revisão manual.</p></section>{/if}
{#if repair && repair.changed}<section class="panel diff"><div class="panel-heading"><h2>Revisão das alterações</h2><span class="badge">Original ↔ Proposta</span></div><div class="diff-grid"><div><h3>Original</h3><pre>{#each diff?.left ?? [] as line}<span class="line {line.kind}">{line.text || ' '}</span>{/each}</pre></div><div><h3>Código corrigido</h3><pre>{#each diff?.right ?? [] as line}<span class="line {line.kind}">{line.text || ' '}</span>{/each}</pre></div></div></section>{/if}
<div class="scope-note"><strong>Escopo do experimento v2</strong><span>Q-Learning: SQLite · Cookies Secure (exigem HTTPS) · Bytes aleatórios do SO.</span><span>Regras gerais: SQL parametrizado · subprocess sem shell · ast.literal_eval · cookies Secure · SystemRandom; abstenção com motivo quando não há reescrita segura.</span></div>
