<script lang="ts">
  import { api, type Analysis, type Repair } from '$lib/api';
  let code = $state('');
  let analysis = $state<Analysis | null>(null);
  let repair = $state<Repair | null>(null);
  let busy = $state('');
  let error = $state('');
  const labels: Record<string,string> = { validated: 'Propriedade SQL validada', proposed: 'Correção proposta', unverified: 'Correção não verificada', unsupported: 'Sem correção automática suportada' };
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
<section class="intro"><div><p class="eyebrow">01 / ANÁLISE ASSISTIDA</p><h1>Entenda o risco.<br/><span>Revise a correção.</span></h1><p class="lead">Inspecione código Python e acompanhe as decisões de uma política aprendida com exemplos públicos da OWASP.</p></div><aside class="scope"><span class="dot"></span> Análise estática<p>O código enviado é tratado como texto.<br/>Correções automáticas têm escopo limitado.</p><a href="/dashboard">Explorar os resultados reais ↗</a></aside></section>
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
      {#if !analysis.syntax_valid}<p class="error">Sintaxe incompatível: {analysis.error}</p>{/if}
      {#each analysis.alerts as alert}<article class="finding"><div class="flex justify-between gap-2"><span class="status detected">Possível vulnerabilidade</span><span class="mono">L{alert.line}</span></div><h3>CWE-{alert.cwe} <span> / {alert.sink}</span></h3><p>{alert.owasp}</p><small>{alert.message}</small></article>{/each}
      {#if analysis.syntax_valid && !analysis.alerts.length}<p class="notice">Nenhum padrão conhecido foi detectado pelas regras AST.</p>{/if}
      <details><summary>Bandit · {analysis.bandit.results.length} alertas ({analysis.bandit.status})</summary>{#each analysis.bandit.results as finding}<p class="bandit-item">L{finding.line_number} · {finding.test_id} — {finding.issue_text}</p>{/each}</details>
      <p class="notice">{analysis.notice}</p>
    {/if}
    {#if repair}<div class="repair-result"><span class="status {repair.status}">{labels[repair.status] || repair.status}</span><h3>Sequência escolhida pelo agente</h3><ol class="trace">{#each repair.actions as action, i}<li><span>{String(i+1).padStart(2,'0')}</span><div><strong>{action.action}</strong><small>{action.outcome}</small></div></li>{/each}</ol><p class="notice">{repair.notice}</p></div>{/if}
  </section>
</div>
{#if repair}<section class="panel diff"><div class="panel-heading"><h2>Revisão das alterações</h2><span class="badge">Original ↔ Proposta</span></div><div class="diff-grid"><div><h3>Original</h3><pre>{repair.original}</pre></div><div><h3>Resultado da política</h3><pre>{repair.modified}</pre></div></div></section>{/if}
<div class="scope-note"><strong>Escopo do experimento</strong><span>SQL Injection: parametrização SQLite restrita.</span><span>Command / Code Injection: análise e abstenção.</span></div>
