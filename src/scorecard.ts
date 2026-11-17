/**
 * Scorecard documents — the signed statement of how an agent behaved under
 * adversarial probing.
 *
 * SIGNED CORE = { v, id, created_at, target, suites, results, summary }
 *
 *   commitment = SHA-256(canonicalJson(core))
 *   signature  = Ed25519(canonicalJson(core))
 *
 * The commitment is anchored on zkVerify (system.remark "spar/v1/<hash>") so
 * a scorecard is provably timestamped and cannot be altered after the fact.
 * `status`/`progress` mutate during a run and are deliberately OUTSIDE the
 * signed core.
 */
import * as crypto from 'node:crypto';
import { verifyBytes } from './keys.js';

export type AuthMode = 'none' | 'hmac';

export interface RunTarget {
  url: string;
  auth_mode: AuthMode;
}

export interface VectorResult {
  suite: string;
  name: string;
  expect: string;
  got: {
    http_status: number | null;
    decision?: string;
    preflight_ok?: boolean;
    reason_code?: string;
    ms: number;
  };
  verdict: 'PASS' | 'FAIL' | 'TIMEOUT' | 'ERROR' | 'SKIPPED';
  delta: number;
  detail?: string;
}

export interface RunSummary {
  total_delta: number;
  max_delta: number;
  pass: number;
  fail: number;
  timeout: number;
  /** Auth-contract vectors not applicable to the chosen auth mode. */
  skipped: number;
  /** The scariest metric: how many traps / garbage inputs the target APPROVED. */
  trap_approved: number;
  grade: 'A' | 'B' | 'C' | 'D';
}

export interface AnchorInfo {
  status: 'disabled' | 'pending' | 'submitted' | 'finalized' | 'failed';
  network?: string;
  remark?: string;
  tx_hash?: string;
  block_hash?: string;
  explorer_url?: string;
  error?: string;
  updated_at?: string;
}

export interface SparRunDoc {
  v: 1;
  id: string;
  created_at: string;
  target: RunTarget;
  suites: string[];
  status: 'queued' | 'running' | 'done' | 'failed';
  progress: { done: number; total: number };
  results: VectorResult[];
  summary: RunSummary | null;
  error?: string;
  commitment: string;
  signature: string;
  anchor: AnchorInfo;
}

export type SignedCore = Pick<
  SparRunDoc,
  'v' | 'id' | 'created_at' | 'target' | 'suites' | 'results' | 'summary'
>;

/** Deterministic JSON: keys sorted recursively, no insignificant whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export function sha256Hex(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function newRunId(): string {
  return `spar_${crypto.randomBytes(8).toString('hex')}`;
}

export function runCore(doc: SparRunDoc): SignedCore {
  const { v, id, created_at, target, suites, results, summary } = doc;
  return { v, id, created_at, target, suites, results, summary };
}

export function computeCommitment(core: SignedCore): string {
  return sha256Hex(canonicalJson(core));
}

/** Offline verification: recompute commitment + verify Ed25519 signature. */
export function verifyRunDoc(
  doc: SparRunDoc,
  publicKeyHex: string,
): { signature_valid: boolean; commitment_matches: boolean } {
  const core = runCore(doc);
  const recomputed = computeCommitment(core);
  const sigOk = verifyBytes(
    Buffer.from(canonicalJson(core), 'utf8'),
    Buffer.from(doc.signature, 'hex'),
    publicKeyHex,
  );
  return { signature_valid: sigOk, commitment_matches: recomputed === doc.commitment };
}
