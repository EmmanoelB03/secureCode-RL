<script lang="ts">
  import type { Point } from './api';
  let { rows, metric, title }: { rows: Point[]; metric: 'reward' | 'epsilon' | 'validated'; title: string } = $props();
  let values = $derived(rows.map(r => r[metric]));
  let min = $derived(Math.min(0, ...values));
  let max = $derived(Math.max(metric === 'reward' ? 1 : 0.01, ...values));
  let points = $derived(rows.map((r, i) => `${40+i/Math.max(1,rows.length-1)*620},${170-(r[metric]-min)/(max-min)*140}`).join(' '));
</script>
<div class="chart"><h3>{title}</h3><svg viewBox="0 0 700 210" role="img" aria-label={title}><line x1="40" y1="170" x2="660" y2="170" stroke="#dce4e2"/><line x1="40" y1="30" x2="660" y2="30" stroke="#edf1f0"/><text x="0" y="35">{max.toFixed(2)}</text><text x="0" y="175">{min.toFixed(2)}</text><polyline fill="none" stroke="#087e71" stroke-width="2.5" {points}/><text x="40" y="200">1</text><text x="570" y="200">{rows.at(-1)?.episode || 0} episódios</text></svg></div>
