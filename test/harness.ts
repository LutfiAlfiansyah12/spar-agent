/**
 * End-to-end local harness. No real network, no secrets, no on-chain access:
 * the target agents are local fixtures, ANCHOR_MODE=none, and the probe URLs
 * stay on 127.0.0.1 (ALLOW_PRIVATE_TARGETS=true — test only).
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { config } from '../src/config.js';
import { initKeys, getKeys, signBytes, verifyBytes } from '../src/keys.js';
import { canonicalJson, verifyRunDoc, newRunId, type SparRunDoc } from '../src/scorecard.js';
import { buildVectors, ALL_SUITES } from '../src/vectors.js';
import { remarkFor } from '../src/anchor.js';
import { initApp } from '../src/server.js';
import { HARNESS_SECRET, startFixture, type Fixture } from './fixtures.js';

let passed = 0;
let failed = 0;

function check(name: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.error(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'spar-test-'));
}

async function waitForDone(base: string, id: string, timeoutMs = 20000): Promise<SparRunDoc> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const doc = (await (await fetch(`${base}/runs/${id}`)).json()) as SparRunDoc;
    if (['done', 'failed'].includes(doc.status)) return doc;
    if (Date.now() > deadline) throw new Error(`run ${id} did not finish in time (status ${doc.status})`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function main(): Promise<void> {
  const fixture = await startFixture();

  // ── crypto plumbing (reused infra) ───────────────────────────────────────
  console.log('\n[signing plumbing]');
  config.dataDir = tmpDir();
  initKeys();
  const pub = getKeys().publicKeyHex;
  check('public key is 32-byte hex', /^[0-9a-f]{64}$/.test(pub));
  const sig = signBytes(Buffer.from('spar'));
  check('signature verifies', verifyBytes(Buffer.from('spar'), sig, pub));
  check('tampered message rejected', !verifyBytes(Buffer.from('spar!'), sig, pub));
  check('remark prefix', remarkFor('abc') === 'spar/v1/abc');

  // ── vector builder ───────────────────────────────────────────────────────
  console.log('\n[vectors]');
  const v1 = buildVectors(newRunId(), [...ALL_SUITES]);
  const v2 = buildVectors(newRunId(), [...ALL_SUITES]);
  check('16 vectors by default', v1.length === 16, `got ${v1.length}`);
  check('suite counts', [
    v1.filter((v) => v.suite === 'preflight').length === 1,
    v1.filter((v) => v.suite === 'valid').length === 2,
    v1.filter((v) => v.suite === 'traps').length === 9,
    v1.filter((v) => v.suite === 'failclosed').length === 4,
  ].every(Boolean));
  const ids1 = v1.map((v) => (v.build() as { task_id?: string }).task_id).filter(Boolean);
  const ids2 = v2.map((v) => (v.build() as { task_id?: string }).task_id).filter(Boolean);
  check('fresh task ids per run', ids1.every((id) => !ids2.includes(id)));
  check('suite subset works', buildVectors(newRunId(), ['valid']).length === 2);

  // ── runner vs honest target (hmac auth) ──────────────────────────────────
  console.log('\n[runner vs honest target]');
  config.dataDir = tmpDir();
  initKeys();
  config.runner.allowPrivateTargets = true;
  config.rateLimit.max = 1000;
  const app = initApp();
  const port = await app.listen();
  const base = `http://127.0.0.1:${port}`;

  const start1 = await (
    await fetch(base + '/spar', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target_url: fixture.url('/honest'),
        auth: 'hmac',
        hmac_secret: HARNESS_SECRET,
      }),
    })
  ).json();
  const doc1 = await waitForDone(base, (start1 as { id: string }).id);
  check('run completes', doc1.status === 'done', doc1.error);
  check('all vectors PASS', doc1.results.every((r) => r.verdict === 'PASS'), `fails: ${doc1.results.filter((r) => r.verdict !== 'PASS').map((r) => r.name).join('; ')}`);
  check('grade A, zero traps approved', doc1.summary?.grade === 'A' && doc1.summary?.trap_approved === 0);
  check('hmac run skips nothing', doc1.summary?.skipped === 0);
  const reuse = doc1.results.find((r) => r.name.includes('proof-reuse'));
  check('reuse trap rejected with reason', reuse?.verdict === 'PASS' && (reuse.detail ?? '').includes('PROOF_REUSED'));
  check('preflight acknowledged', doc1.results.find((r) => r.suite === 'preflight')?.verdict === 'PASS');
  const v1ok = verifyRunDoc(doc1, getKeys().publicKeyHex);
  check('scorecard self-verifies', v1ok.signature_valid && v1ok.commitment_matches);
  check('secret not persisted', !JSON.stringify(doc1).toLowerCase().includes('secret'), 'hmac secret leaked into doc!');

  const tampered: SparRunDoc = JSON.parse(JSON.stringify(doc1));
  tampered.results[0].delta += 1;
  const vt = verifyRunDoc(tampered, getKeys().publicKeyHex);
  check('tampered scorecard detected', !vt.signature_valid && !vt.commitment_matches);

  // ── runner vs greedy target (no auth) ────────────────────────────────────
  console.log('\n[runner vs greedy target]');
  const start2 = await (
    await fetch(base + '/spar', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target_url: fixture.url('/greedy'), auth: 'none' }),
    })
  ).json();
  const doc2 = await waitForDone(base, (start2 as { id: string }).id);
  check('greedy run completes', doc2.status === 'done');
  // preflight +12, valid +24, traps 9x -6 = -54, failclosed garbage/empty 2x -6 = -12
  // (tamper/omit SKIPPED — auth-contract vectors need hmac mode)
  check('greedy skips auth-contract vectors', doc2.summary?.skipped === 2);
  check('greedy score is -30', doc2.summary?.total_delta === -30, `got ${doc2.summary?.total_delta}`);
  check('greedy approved 11 traps/garbage', doc2.summary?.trap_approved === 11, `got ${doc2.summary?.trap_approved}`);
  check('greedy grade D', doc2.summary?.grade === 'D');

  // ── open target (no-auth honest) ─────────────────────────────────────────
  console.log('\n[runner vs open (no-auth) target]');
  const start3 = await (
    await fetch(base + '/spar', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target_url: fixture.url('/open'), auth: 'none' }),
    })
  ).json();
  const doc3 = await waitForDone(base, (start3 as { id: string }).id);
  check('open target: auth-contract vectors SKIPPED, delta 0', doc3.results
    .filter((r) => r.suite === 'failclosed' && (r.name.includes('tampered') || r.name.includes('missing')))
    .every((r) => r.verdict === 'SKIPPED' && r.delta === 0));
  check('open target: traps all rejected', doc3.summary?.trap_approved === 0);
  check('open target: grade A (honest no-auth agent)', doc3.summary?.grade === 'A' && doc3.summary?.total_delta === 168);

  // ── auth-all-rejected flag ───────────────────────────────────────────────
  console.log('\n[auth-all-rejected detection]');
  const start4 = await (
    await fetch(base + '/spar', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target_url: fixture.url('/strict401'), auth: 'hmac', hmac_secret: HARNESS_SECRET }),
    })
  ).json();
  const doc4 = await waitForDone(base, (start4 as { id: string }).id);
  check('strict401 run completes', doc4.status === 'done');
  check('auth_all_rejected flagged', doc4.summary?.auth_all_rejected === true);

  // ── SSRF guard ───────────────────────────────────────────────────────────
  console.log('\n[SSRF guard]');
  config.runner.allowPrivateTargets = false;
  const blocked = await (
    await fetch(base + '/spar', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target_url: fixture.url('/honest'), auth: 'none' }),
    })
  ).json();
  // validateTargetUrl rejects at request parse time? hostname 127.0.0.1 passes URL check;
  // the DNS resolve step inside the run marks it failed.
  const blockedId = (blocked as { id: string }).id;
  const blockedDoc = await waitForDone(base, blockedId);
  check('private target run rejected', blockedDoc.status === 'failed' && (blockedDoc.error ?? '').includes('private'), blockedDoc.error);

  const metaBlocked = await fetch(base + '/spar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ target_url: 'http://169.254.169.254/latest/meta-data/', auth: 'none' }),
  });
  check('metadata IP run rejected', metaBlocked.status === 200 || metaBlocked.status === 400);
  if (metaBlocked.status === 200) {
    const md = await waitForDone(base, ((await metaBlocked.json()) as { id: string }).id);
    check('metadata IP flagged', md.status === 'failed');
  }

  config.runner.allowPrivateTargets = true;

  // ── request validation ───────────────────────────────────────────────────
  console.log('\n[request validation]');
  const bad1 = await fetch(base + '/spar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ target_url: fixture.url('/honest'), auth: 'hmac' }),
  });
  check('hmac without secret 400', bad1.status === 400);
  const bad2 = await fetch(base + '/spar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ target_url: fixture.url('/honest'), suites: ['nonsense'] }),
  });
  check('unknown suite 400', bad2.status === 400);
  const bad3 = await fetch(base + '/spar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ target_url: 'ftp://x', auth: 'none' }),
  });
  check('bad scheme 400', bad3.status === 400);

  // ── HTTP plumbing ────────────────────────────────────────────────────────
  console.log('\n[HTTP plumbing]');
  const health = await (await fetch(base + '/healthz')).json();
  check('healthz ok', (health as { ok: boolean }).ok === true);
  const pk = await (await fetch(base + '/publickey')).json();
  check('publickey matches', (pk as { public_key_hex: string }).public_key_hex === getKeys().publicKeyHex);
  const home = await fetch(base + '/');
  check('demo page served', home.status === 200 && (await home.text()).includes('Spar'));
  const rep = await (await fetch(`${base}/runs/${doc1.id}/report`)).json();
  check('report endpoint verifies', (rep as { verification: { signature: { valid: boolean } } }).verification.signature.valid === true);
  const nf = await fetch(base + '/runs/spar_unknown');
  check('unknown run 404', nf.status === 404);

  // rate limiting (fresh bucket would pass 2, existing bucket may already be hot)
  config.rateLimit.max = 1;
  let got429 = false;
  for (let i = 0; i < 3; i++) {
    const r = await fetch(base + '/spar', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target_url: fixture.url('/honest'), auth: 'none' }),
    });
    if (r.status === 429) got429 = true;
  }
  check('rate limiter caps runs', got429);

  app.server.close();
  fixture.close();

  console.log(`\n════════════════════════════════════`);
  console.log(`  ${passed} passed, ${failed} failed`);
  console.log(`════════════════════════════════════`);
  if (failed > 0) process.exitCode = 1;
}

void main().catch((e) => {
  console.error('HARNESS CRASH:', e);
  process.exitCode = 1;
});
