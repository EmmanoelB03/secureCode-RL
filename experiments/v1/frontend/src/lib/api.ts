export async function api<T>(path: string, code?: string): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, code === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code })
  });
  const result = await response.json();
  if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Entrada inválida. Limite: 50.000 caracteres.');
  return result as T;
}
export type Alert = { cwe: number; line: number; sink: string; message: string; owasp: string };
export type Analysis = { alerts: Alert[]; syntax_valid: boolean; error: string | null; notice: string; bandit: { status: string; results: { test_id: string; issue_text: string; line_number: number }[] } };
export type Repair = { original: string; modified: string; status: string; notice: string; actions: { action: string; outcome: string; reward: number }[]; validation: { security_verified: boolean; functional_verified: boolean; scope: string } | null };
export type Metrics = { examples: number; positives: number; treatable: number; validated: number; unsupported: number; mean_reward: number; mean_actions: number; validated_correction_rate: number | null; treatable_correction_rate: number | null; unnecessary_change_rate: number | null; actions: Record<string, number> };
export type Experiment = { id: string; policy: string; seed: number; metrics: Metrics; by_cwe: Record<string, Metrics> };
export type Point = { episode: number; reward: number; epsilon: number; validated: number };
export type Dashboard = { training: { selected_seed: number; runs: { seed: number; episodes: number; config: Record<string, unknown> }[] }; evaluation: { experiments: Experiment[]; caveat: string }; curves: Record<string, Point[]> };
export type Dataset = { dataset: string; version: string; total: number; selected: number; commit: string; url: string; splits: Record<string, { count: number }>; distribution: Record<string, number> };
