/**
 * Fake target agents for the harness — implements the Proof Gatekeeper
 * decision contract in miniature:
 *
 *   /honest — verifies HMAC, runs the checklist, approves valid tasks,
 *             rejects every trap, 401 on auth failure (fail-closed)
 *   /greedy — approves everything non-preflight (the anti-pattern Spar
 *             exists to catch)
 *   /open   — honest engine WITHOUT auth (for auth:"none" probing)
 */
import * as crypto from 'node:crypto';
import * as http from 'node:http';

export const HARNESS_SECRET = 'spar-harness-test-secret';
export const VALID_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function computeHmac(rawBody: Buffer, secret: string): string {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function parseHeader(header: string | undefined): string | null {
  if (!header) return null;
  const h = header.trim();
  if (h.toLowerCase().startsWith('sha256=')) return h.slice(7).trim();
  if (h.toLowerCase().startsWith('v1=')) return h.slice(3).trim();
  if (/^[0-9a-fA-F]{64}$/.test(h)) return h.toLowerCase();
  return null;
}

class HonestEngine {
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

export interface Fixture {
  server: http.Server;
  port: number;
  close: () => void;
  url: (p: string) => string;
}

export function startFixture(): Promise<Fixture> {
  const honestHmac = new HonestEngine();
  const honestOpen = new HonestEngine();
  const greedy = new HonestEngine();

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      const p = req.url?.split('?')[0] ?? '/';
      const send = (code: number, obj: Record<string, unknown>) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(obj));
      };

      if (p === '/honest') {
        const sig = parseHeader(req.headers['x-agent-games-signature'] as string | undefined);
        if (!sig || sig !== computeHmac(raw, HARNESS_SECRET)) {
          send(401, { error: 'invalid signature' });
          return;
        }
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
        } catch {
          send(400, { error: 'unparseable body' });
          return;
        }
        send(200, honestHmac.decide(body));
        return;
      }

      if (p === '/open') {
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
        } catch {
          send(400, { error: 'unparseable body' });
          return;
        }
        send(200, honestOpen.decide(body));
        return;
      }

      if (p === '/strict401') {
        // Auth layer that rejects EVERYTHING — even valid signatures
        // (simulates a secret/header mismatch on the target).
        send(401, { error: 'invalid signature' });
        return;
      }

      if (p === '/greedy') {
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
        } catch {
          send(200, { decision: 'APPROVE', reason_code: 'YOLO' });
          return;
        }
        if (body.type === 'agent-games.preflight.v1') send(200, { ok: true, protocolVersion: 'v1' });
        else send(200, { decision: 'APPROVE', reason_code: 'YOLO' });
        return;
      }

      send(404, { error: 'not found' });
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolve({
        server,
        port,
        close: () => server.close(),
        url: (p: string) => `http://127.0.0.1:${port}${p}`,
      });
    });
  });
}
