/**
 * Public HTTP surface.
 *
 *   GET  /               → demo page (public/index.html)
 *   GET  /healthz        → liveness + config fingerprint
 *   GET  /publickey      → Ed25519 public key for offline verification
 *   POST /spar           → start an eval run against a target agent
 *   GET  /runs/:id       → run document (live progress)
 *   GET  /runs/:id/report→ signed scorecard + verification report
 *
 * Safety: per-IP rate limiting on POST /spar; target URLs are SSRF-validated;
 * HMAC secrets provided for a run are memory-only.
 */
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { log } from './log.js';
import { getKeys } from './keys.js';
import { verifyRunDoc } from './scorecard.js';
import { SparStore } from './store.js';
import { AnchorWorker } from './anchor.js';
import { createRun, parseSparRequest, SparRequestError, RunWorker } from './runner.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../public');

// ── Rate limiter (per-IP fixed window, POST /spar only) ─────────────────────

const buckets = new Map<string, { count: number; resetAt: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || b.resetAt <= now) {
    buckets.set(ip, { count: 1, resetAt: now + config.rateLimit.windowMs });
    return false;
  }
  b.count += 1;
  return b.count > config.rateLimit.max;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (v.resetAt <= now) buckets.delete(k);
}, 60_000).unref();

// ── Helpers ──────────────────────────────────────────────────────────────────

const MAX_REQUEST_BODY = 8 * 1024;

function json(res: http.ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  });
  res.end(data);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > MAX_REQUEST_BODY) {
        reject(new SparRequestError('TOO_LARGE', 'request body exceeds 8KB'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const STATUS_FOR_CODE: Record<string, number> = {
  BAD_REQUEST: 400,
  TOO_LARGE: 413,
  BLOCKED_TARGET: 403,
  DNS_FAILURE: 502,
};

// ── App wiring ───────────────────────────────────────────────────────────────

export interface App {
  server: http.Server;
  store: SparStore;
  worker: RunWorker;
  anchor: AnchorWorker;
  listen: () => Promise<number>;
}

export function initApp(): App {
  const store = new SparStore(config.dataDir);
  const anchor = new AnchorWorker();
  anchor.start(store);
  const worker = new RunWorker();
  worker.start(store, anchor);

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const url = new URL(req.url ?? '/', 'http://local');
    const finish = (status: number) =>
      log.info('req', { method: req.method, path: url.pathname, status, ms: Date.now() - started });

    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'access-control-allow-origin': '*',
          'access-control-allow-headers': 'content-type',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
        });
        res.end();
        return;
      }

      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'));
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(html);
        finish(200);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/healthz') {
        json(res, 200, {
          ok: true,
          uptime_s: Math.round(process.uptime()),
          anchor_mode: config.anchor.mode,
          runs_stored: store.size,
          allow_private_targets: config.runner.allowPrivateTargets,
        });
        finish(200);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/publickey') {
        json(res, 200, {
          algorithm: 'Ed25519',
          public_key_hex: getKeys().publicKeyHex,
          usage:
            'Verify any scorecard: canonicalJson(core) must (a) hash to commitment (SHA-256) and (b) verify under this key. Core = run doc minus status/progress/commitment/signature/anchor.',
        });
        finish(200);
        return;
      }

      if (req.method === 'POST' && url.pathname === '/spar') {
        const ip = req.socket.remoteAddress ?? 'unknown';
        if (rateLimited(ip)) {
          json(res, 429, { error: { code: 'RATE_LIMITED', message: 'too many runs — slow down' } });
          finish(429);
          return;
        }
        const raw = await readBody(req);
        let body: unknown;
        try {
          body = raw ? JSON.parse(raw) : {};
        } catch {
          json(res, 400, { error: { code: 'BAD_REQUEST', message: 'body must be JSON' } });
          finish(400);
          return;
        }
        const parsed = parseSparRequest(body);
        const doc = createRun(parsed, { store, worker, anchor });
        json(res, 200, {
          id: doc.id,
          status: doc.status,
          suites: doc.suites,
          poll: `/runs/${doc.id}`,
        });
        finish(200);
        return;
      }

      const runMatch = url.pathname.match(/^\/runs\/([A-Za-z0-9_\-]{3,64})$/);
      if (req.method === 'GET' && runMatch) {
        const doc = store.get(runMatch[1]);
        if (!doc) {
          json(res, 404, { error: { code: 'NOT_FOUND', message: 'unknown run id' } });
          finish(404);
          return;
        }
        json(res, 200, doc);
        finish(200);
        return;
      }

      const reportMatch = url.pathname.match(/^\/runs\/([A-Za-z0-9_\-]{3,64})\/report$/);
      if (req.method === 'GET' && reportMatch) {
        const doc = store.get(reportMatch[1]);
        if (!doc) {
          json(res, 404, { error: { code: 'NOT_FOUND', message: 'unknown run id' } });
          finish(404);
          return;
        }
        const v = verifyRunDoc(doc, getKeys().publicKeyHex);
        json(res, 200, {
          run_id: doc.id,
          target: doc.target,
          status: doc.status,
          grade: doc.summary?.grade ?? null,
          summary: doc.summary,
          verification: {
            signature: { algorithm: 'Ed25519', valid: v.signature_valid, public_key_hex: getKeys().publicKeyHex },
            commitment: {
              algorithm: 'SHA-256 over canonical JSON of the scorecard core',
              value: doc.commitment,
              matches: v.commitment_matches,
            },
            anchor: {
              status: doc.anchor.status,
              network: doc.anchor.network,
              remark: doc.anchor.remark,
              tx_hash: doc.anchor.tx_hash,
              explorer_url: doc.anchor.explorer_url,
              how_to_check: doc.anchor.tx_hash
                ? 'Open the explorer URL and compare the system.remark argument with the commitment above (prefix spar/v1/).'
                : 'Anchor not finalized yet (or disabled with ANCHOR_MODE=none).',
            },
          },
          run: doc,
        });
        finish(200);
        return;
      }

      json(res, 404, { error: { code: 'NOT_FOUND', message: 'unknown route' } });
      finish(404);
    } catch (e) {
      if (e instanceof SparRequestError) {
        json(res, STATUS_FOR_CODE[e.code] ?? 400, { error: { code: e.code, message: e.message } });
        finish(STATUS_FOR_CODE[e.code] ?? 400);
        return;
      }
      log.error('unhandled error', { error: String((e as Error).stack ?? e).slice(0, 400) });
      json(res, 500, { error: { code: 'INTERNAL', message: 'internal error' } });
      finish(500);
    }
  });

  return {
    server,
    store,
    worker,
    anchor,
    listen: () =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.server.port, config.server.host, () => {
          const addr = server.address();
          resolve(typeof addr === 'object' && addr ? addr.port : config.server.port);
        });
      }),
  };
}
