/**
 * Built-in practice targets — miniature decision agents served BY spar
 * itself, so anyone can run a spar without owning (or having secrets for)
 * another agent:
 *
 *   POST /practice-target        — honest implementation: acknowledges
 *                                  preflight, approves valid tasks, rejects
 *                                  every trap, fail-closed on garbage.
 *   POST /practice-target-greedy — approves everything non-preflight (the
 *                                  anti-pattern; expect grade D).
 *
 * Both accept plain POSTs (auth "none"): auth-contract vectors are skipped
 * by the runner, which is itself part of the demonstration.
 *
 * These are REAL routes on the public endpoint — spar against them via the
 * public URL. They are also used (with an HMAC wrapper) by the test harness.
 */

import { VALID_VK } from './vectors.js';

export class HonestEngine {
  private consumedTx = new Set<string>();

  decide(body: Record<string, unknown>): Record<string, unknown> {
    if (body.type === 'agent-games.preflight.v1') {
      return { ok: true, protocolVersion: 'v1' };
    }
    if (body.type !== 'agent-games.proof-gatekeeper.v1') {
      return { decision: 'REJECT', reason_code: 'MALFORMED' };
    }
    const input = (body.input ?? {}) as Record<string, unknown>;
    const reject = (code: string) => ({ decision: 'REJECT', reason_code: code });

    if (input.registered_vk !== VALID_VK || input.proof_vk !== VALID_VK) {
      return input.registered_vk !== VALID_VK ? reject('CIRCUIT_MISMATCH') : reject('VK_SUBSTITUTION');
    }
    const num = (v: unknown) => Number(v);
    if (num(input.public_balance) < num(input.minimum)) return reject('INSUFFICIENT_BALANCE');
    if (input.recipient !== input.condition_recipient) return reject('RECIPIENT_MISMATCH');
    if (num(input.amount) > num(input.max_transfer)) return reject('AMOUNT_EXCEEDS_LIMIT');
    if (num(input.current_block) >= num(input.expiry_block)) return reject('CONDITION_EXPIRED');

    const issued = Date.parse(String(body.issued_at ?? ''));
    const deadline = Date.parse(String(body.deadline_at ?? ''));
    const now = Date.now();
    if (!Number.isFinite(issued) || issued > now + 300_000) return reject('INVALID_TIMESTAMP');
    if (!Number.isFinite(deadline) || deadline <= now) return reject('DEADLINE_EXCEEDED');

    const proofTx = String(input.proof_tx ?? '');
    if (!proofTx.startsWith('0x')) return reject('MALFORMED');
    if (this.consumedTx.has(proofTx)) return reject('PROOF_REUSED');

    this.consumedTx.add(proofTx);
    return { decision: 'APPROVE', reason_code: 'ALL_CHECKS_PASSED' };
  }
}

export const PRACTICE_TARGET = '/practice-target';
export const PRACTICE_GREEDY = '/practice-target-greedy';

const honest = new HonestEngine();

/**
 * Returns a response for practice-target routes, or null if `pathname` is
 * not one. Responses follow the signed-contract shape ({decision} /
 * {ok:true}) so the spar classifier handles them like any agent.
 */
export function handlePractice(
  pathname: string,
  rawBody: Buffer,
): { status: number; body: Record<string, unknown> } | null {
  const send = (status: number, body: Record<string, unknown>) => ({ status, body });

  if (pathname === PRACTICE_TARGET) {
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(rawBody.toString('utf8')) as Record<string, unknown>;
    } catch {
      return send(400, { error: 'unparseable body' });
    }
    return send(200, honest.decide(body));
  }

  if (pathname === PRACTICE_GREEDY) {
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(rawBody.toString('utf8')) as Record<string, unknown>;
    } catch {
      return send(200, { decision: 'APPROVE', reason_code: 'YOLO' });
    }
    if (body.type === 'agent-games.preflight.v1') return send(200, { ok: true, protocolVersion: 'v1' });
    return send(200, { decision: 'APPROVE', reason_code: 'YOLO' });
  }

  return null;
}
