export async function api<T>(path: string, code?: string): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, code === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code })
  });
  const result = await response.json();
  if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Entrada inválida. Limite: 50.000 caracteres.');
  return result as T;
}
export type Alert = { cwe: number; line: number; sink: string; message: string; owasp: string };
export type Analysis = { classification?: { status: string; label: string; positive?: boolean; model?: string; version?: string; notice?: string }; alerts: Alert[]; syntax_valid: boolean; error: string | null; notice: string; bandit: { status: string; results: { test_id: string; issue_text: string; line_number: number }[] } };
export type Repair = { original: string; modified: string; changed: boolean; status: string; notice: string; actions: { action: string; outcome: string; reward: number | null; source?: string; detail?: string }[]; validation: { security_verified: boolean; functional_verified: boolean; scope: string } | null; unfixed: { cwe: number; line: number; reason: string }[]; alerts: { cwe: number; line: number; sink: string }[] };
export type Metrics = { examples: number; positives: number; treatable: number; validated: number; unsupported: number; mean_reward: number; mean_actions: number; unseen_state_actions: number; validated_correction_rate: number | null; treatable_correction_rate: number | null; unnecessary_change_rate: number | null; actions: Record<string, number> };
export type Experiment = { id?: string; fold?: number; policy: string; seed: number; metrics: Metrics; by_cwe: Record<string, Metrics> };
export type Point = { episode: number; reward: number; epsilon: number; validated: number };
export type FoldPartition = { count: number; treatable: number };
export type Dashboard = { training: { selected_seed: number; runs: { seed: number; episodes: number; config: Record<string, unknown> }[] }; evaluation: { experiments: Experiment[]; caveat: string }; curves: Record<string, Point[]>; cross_validation: { examples: number; groups: number; folds: { fold: number; train: FoldPartition; validation: FoldPartition; test: FoldPartition }[]; pooled: Experiment[]; experiments: Experiment[] } };
export type ClassMetrics = { examples: number; precision: number; recall: number; f1_positive: number; macro_f1: number; balanced_accuracy: number; accuracy: number; confusion: { tn: number; fp: number; fn: number; tp: number } };
export type SupervisedRow = { seed: number; representation: 'raw' | 'cleaned'; policy: string; metrics: ClassMetrics; by_cwe: Record<string, ClassMetrics>; fold_f1: number[]; mean_inference_ms_per_file: number };
export type FoldSelection = { seed?: number; representation: string; fold: number; policy: string; selection: Record<string, unknown>; metrics: ClassMetrics; converged?: boolean };
type MetricKey = 'precision' | 'recall' | 'f1_positive' | 'macro_f1' | 'balanced_accuracy';
export type MlpAgg = { f1_mean: number; f1_std: number; f1_by_seed: number[]; seeds?: number[]; metrics_mean?: Record<MetricKey, number>; metrics_std: Record<MetricKey, number>; fp_mean: number; fn_mean: number };
export type Supervised = { examples: number; folds: number; seed: number; summary: SupervisedRow[]; fold_selection: FoldSelection[]; mlp: { seeds: number[]; grid: { hidden_layer_sizes: number[]; alpha: number }[]; note: string; post_hoc: boolean; across_seeds?: Record<string, MlpAgg> } | null };
export type Dataset ={ dataset: string; version: string; total: number; selected: number; commit: string; url: string; splits: Record<string, { count: number }>; distribution: Record<string, number> };
