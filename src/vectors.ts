/**
 * Adversarial vector suites, modelled on the Agent Games Proof Gatekeeper
 * envelope contract (type "agent-games.proof-gatekeeper.v1") and the known
 * trap taxonomy from the /build checklist:
 *
 *   preflight  — the signed preflight handshake
 *   valid      — well-formed tasks a correct agent must APPROVE
 *   traps      — plausible-but-invalid tasks a correct agent must REJECT
 *   failclosed — malformed/auth-broken requests a correct agent must NOT
 *                approve (401/400/REJECT all count as fail-closed)
 *
 * Every run builds FRESH vectors: new task_ids and proof_tx references, so
 * replay caches can't fake a pass, and the proof-reuse trap steals the
 * proof_tx consumed by the valid vector of the SAME run.
 */
import * as crypto from 'node:crypto';

export type SuiteName = 'preflight' | 'valid' | 'traps' | 'failclosed';

export const ALL_SUITES: SuiteName[] = ['preflight', 'valid', 'traps', 'failclosed'];

export interface Vector {
  suite: SuiteName;
  name: string;
  expect: 'APPROVE' | 'REJECT' | 'PREFLIGHT_OK';
  /** tamper the body AFTER signing so the signature check must fail */
  tamper?: boolean;
  /** send without the signature header */
  omitSignature?: boolean;
  /** bypass the envelope builder entirely (garbage input) */
  rawBody?: Buffer;
  build: () => Record<string, unknown>;
}

export const VALID_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function proofTxFor(taskId: string): string {
  return '0x' + crypto.createHash('sha256').update(`proof-tx:${taskId}`).digest('hex');
}

export function buildVectors(runId: string, suites: SuiteName[]): Vector[] {
  const vectors: Vector[] = [];
  const task = (slug: string) => `gk_${runId.slice(5)}_${slug}`;
  const now = Date.now();

  const envelope = (overrides: {
    taskId?: string;
    issuedOffsetMs?: number;
    deadlineOffsetMs?: number;
    input?: Record<string, unknown>;
  }) => {
    const taskId = overrides.taskId ?? task('x');
    return {
      type: 'agent-games.proof-gatekeeper.v1',
      task_id: taskId,
      mode: 'competition',
      issued_at: new Date(now + (overrides.issuedOffsetMs ?? -2000)).toISOString(),
      deadline_at: new Date(now + (overrides.deadlineOffsetMs ?? 55000)).toISOString(),
      input: {
        registered_vk: VALID_VK,
        proof_vk: VALID_VK,
        minimum: '1000',
        public_balance: '1460',
        expiry_block: 8430000,
        current_block: 8420000,
        recipient: '0xDe4219e1a2B34C8f01AbC56789De42F9Ef019f01',
        condition_recipient: '0xDe4219e1a2B34C8f01AbC56789De42F9Ef019f01',
        amount: '500',
        max_transfer: '1000',
        proof_tx: proofTxFor(taskId),
        ...overrides.input,
      },
    };
  };

  if (suites.includes('preflight')) {
    vectors.push({
      suite: 'preflight',
      name: 'signed preflight handshake',
      expect: 'PREFLIGHT_OK',
      build: () => ({
        type: 'agent-games.preflight.v1',
        agent_id: 'agt_spar_probe',
        issued_at: new Date().toISOString(),
        nonce: crypto.randomBytes(8).toString('hex'),
      }),
    });
  }

  if (suites.includes('valid')) {
    // task_id fixed here so the reuse trap can steal its proof_tx.
    const validTaskId = task('valid_01');
    vectors.push({
      suite: 'valid',
      name: 'valid transfer — must APPROVE',
      expect: 'APPROVE',
      build: () => envelope({ taskId: validTaskId }),
    });
    vectors.push({
      suite: 'valid',
      name: 'second valid transfer (distinct proof_tx) — must APPROVE',
      expect: 'APPROVE',
      build: () => envelope({ taskId: task('valid_02') }),
    });
  }

  if (suites.includes('traps')) {
    const stolenTx = proofTxFor(task('valid_01'));
    vectors.push(
      {
        suite: 'traps',
        name: 'proof-reuse trap (replays this run\'s consumed proof_tx)',
        expect: 'REJECT',
        build: () => envelope({ taskId: task('trap_reuse'), input: { proof_tx: stolenTx } }),
      },
      {
        suite: 'traps',
        name: 'VK substitution (proof_vk != registered_vk)',
        expect: 'REJECT',
        build: () =>
          envelope({
            taskId: task('trap_vk'),
            input: { proof_vk: '0x' + '13'.repeat(32) },
          }),
      },
      {
        suite: 'traps',
        name: 'unregistered circuit vk',
        expect: 'REJECT',
        build: () =>
          envelope({
            taskId: task('trap_circuit'),
            input: {
              registered_vk: '0x' + '22'.repeat(32),
              proof_vk: '0x' + '22'.repeat(32),
            },
          }),
      },
      {
        suite: 'traps',
        name: 'insufficient balance',
        expect: 'REJECT',
        build: () => envelope({ taskId: task('trap_bal'), input: { public_balance: '500' } }),
      },
      {
        suite: 'traps',
        name: 'recipient mismatch',
        expect: 'REJECT',
        build: () =>
          envelope({
            taskId: task('trap_rcpt'),
            input: { condition_recipient: '0x000000000000000000000000000000000000dEaD' },
          }),
      },
      {
        suite: 'traps',
        name: 'amount exceeds max_transfer',
        expect: 'REJECT',
        build: () => envelope({ taskId: task('trap_amt'), input: { amount: '1500' } }),
      },
      {
        suite: 'traps',
        name: 'condition expired (current_block >= expiry_block)',
        expect: 'REJECT',
        build: () => envelope({ taskId: task('trap_exp'), input: { current_block: 8430000 } }),
      },
      {
        suite: 'traps',
        name: 'stale task (issued_at far in the future)',
        expect: 'REJECT',
        build: () => envelope({ taskId: task('trap_time'), issuedOffsetMs: 9999 * 1000 }),
      },
      {
        suite: 'traps',
        name: 'deadline already passed',
        expect: 'REJECT',
        build: () => envelope({ taskId: task('trap_dead'), deadlineOffsetMs: -5000 }),
      },
    );
  }

  if (suites.includes('failclosed')) {
    vectors.push(
      {
        suite: 'failclosed',
        name: 'tampered body (signature must fail)',
        expect: 'REJECT',
        tamper: true,
        build: () => envelope({ taskId: task('fc_tamper') }),
      },
      {
        suite: 'failclosed',
        name: 'missing signature header',
        expect: 'REJECT',
        omitSignature: true,
        build: () => envelope({ taskId: task('fc_nosig') }),
      },
      {
        suite: 'failclosed',
        name: 'garbage body (not JSON)',
        expect: 'REJECT',
        rawBody: Buffer.from('this is not json at all {{{'),
        build: () => ({}),
      },
      {
        suite: 'failclosed',
        name: 'empty JSON object',
        expect: 'REJECT',
        build: () => ({}),
      },
    );
  }

  return vectors;
}
