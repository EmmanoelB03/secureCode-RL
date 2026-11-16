<script lang="ts">
  import '../style.css';
  import { page } from '$app/state';
  let { children } = $props();
</script>
<svelte:head><title>SecureCode RL · Laboratório de segurança</title><meta name="description" content="Análise estática e experimento de Q-Learning sobre o OWASP Benchmark Python."/></svelte:head>
<header>
  <a class="brand" href="/"><span class="brand-mark">S<span> / </span>C</span><span>SecureCode <strong>RL</strong></span></a>
  <nav aria-label="Navegação principal"><a class:active={page.url.pathname === '/'} href="/">Analisador</a><a class:active={page.url.pathname === '/dashboard'} href="/dashboard">Experimentos</a></nav>
  <span class="lab-label">LABORATÓRIO / 0.1</span>
</header>
<main>{@render children()}</main>
<footer><span>SecureCode RL · Pesquisa em correção assistida</span><span>OWASP Benchmark Python / Q-Learning tabular</span></footer>
