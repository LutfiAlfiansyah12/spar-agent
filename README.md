# Spar — adversarial self-testing gym for decision agents

**Agent Games (Wildcard)** — Spar probes **your own** decision agent the way the
platform will: trap vectors, valid tasks, and broken requests. It grades the
behaviour, signs the scorecard (Ed25519), commits to it (SHA-256 over canonical
JSON), and anchors the commitment on **zkVerify** — so "my agent fails closed"
becomes a checkable claim, not a promise.

**One-line pitch:** before a tournament scores your agent for real (+12 correct,
−6 trap approved), spar against it first — and publish the scorecard with a
chain-timestamped proof.

## The problem it solves

Decision agents (payment approvers, access grantors, oracle routers) fail in
ways that only show up under adversarial input: an agent that approves a
**trap** is the worst possible failure, and you find out about it after the
platform (or an attacker) sends the trap. Today there is no easy way to test
"does my agent reject all the classic traps?" and even less way to *prove* the
result to others.

Spar fixes both halves:

1. **Probing** — it sends a fixed, documented taxonomy of vectors to your
   endpoint and classifies every response.
2. **Proof** — the resulting scorecard is signed, hash-committed, and anchored
   on zkVerify (`system.remark` with payload `spar/v1/<commitment>`), so the
   grade you claim is the grade that happened, timestamped on-chain.

## Who it helps

- **Agent Games participants** — self-test a Proof Gatekeeper agent before
  scored rounds; the trap taxonomy mirrors the /build checklist (proof reuse,
  VK substitution, circuit mismatch, balance, recipient, amount, expiry,
  timestamp, deadline) plus auth fail-closed vectors (tampered / missing
  signature, garbage body).
- **Any builder of decision agents** — a pre-production regression gym: run
  Spar after every change to your decision logic.
- **Reviewers/auditors** — a spar scorecard with an on-chain anchor is a
  compact, verifiable statement of an agent's adversarial robustness at time T.

## The vector taxonomy (4 suites, 16 vectors)

| Suite | Vectors | A correct agent must… |
|---|---|---|
| `preflight` | 1 | acknowledge the signed handshake (`ok: true`) |
| `valid` | 2 | APPROVE well-formed tasks (fresh `proof_tx` each) |
| `traps` | 9 | REJECT: proof reuse (steals the proof_tx consumed by this run's own valid vector), VK substitution, unregistered circuit VK, insufficient balance, recipient mismatch, amount > max, expired condition, future-issued timestamp, passed deadline |
| `failclosed` | 4 | NOT approve: tampered body, missing signature, garbage body, empty object — 401/400/REJECT all count as fail-closed |

Every run builds **fresh vectors** (new task_ids, new proof_tx references), so
a target can't pass by replaying cached answers.

**Scoring** mirrors the platform's model: correct decision `+12`, trap approved
`−6`, valid task rejected `−3`, timeout/offline `−2`. Grades: A ≥ 90%, B ≥ 70%,
C ≥ 50%, else D. The single most important line in every scorecard is
**`trap_approved` — how many traps the target APPROVED (must be 0)**.

Auth-contract vectors (tampered/missing signature) are automatically marked
`SKIPPED` when probing an agent in `auth: "none"` mode — they only make sense
against the signed contract.

## Usage

```bash
curl -sS -X POST https://<spar-host>/spar \
  -H 'content-type: application/json' \
  -d '{
    "target_url": "https://your-agent.example.com/agent",
    "auth": "hmac",
    "hmac_secret": "<THE AGENTS OWN TEST SECRET>",
    "suites": ["preflight", "valid", "traps", "failclosed"]
  }'
```

- `auth: "hmac"` signs every probe with `x-agent-games-signature: sha256=…`
  over the raw body (the Agent Games contract). **The secret is used in memory
  for that single run and never stored or logged.**
- `auth: "none"` sends plain POSTs (for agents without signature auth).

The response returns a run id immediately; runs execute in the background:

```bash
curl -sS https://<spar-host>/runs/<id>          # live progress + results
curl -sS https://<spar-host>/runs/<id>/report   # signed scorecard + verification report
```

The report re-checks the signature and commitment, and includes the anchor
status + explorer link once the remark is finalized.

Demo UI: open `/` in a browser, paste your agent URL + optional test secret,
watch the vector table fill in.

## Trust model & honest limitations

| Aspect | Status |
|---|---|
| Scorecard content was not altered after the run | ✅ signature + commitment |
| Scorecard existed at time T | ✅ on-chain (finalized remark) |
| The target's responses were honestly replayed into the scorecard | ⚠️ trusted to Spar (open source; self-hostable) |
| The target is actually the agent you think it is | ⚠️ you provide the URL; Spar probes whatever answers it |

Stated plainly:

- Spar measures **decision behaviour**, not proof quality — it does not verify
  your Groth16 proofs, only the approve/reject surface.
- Probing **other people's agents without consent** is not the intended use.
  Spar exists for self-testing; only point it at agents you own or control.
- The HMAC secret handling is memory-only by design, but self-host if you want
  zero third-party involvement.

## Repository layout

```
├── public/index.html      # self-contained demo UI (vector table + grades)
├── src/
│   ├── main.ts            # entry point
│   ├── server.ts          # HTTP surface: /spar, /runs/:id, /runs/:id/report
│   ├── config.ts          # env-only configuration
│   ├── vectors.ts         # the 16-vector taxonomy, fresh per run
│   ├── runner.ts          # SSRF-guarded probe worker, classifier, signer
│   ├── hmac.ts            # the Agent Games signed-contract client
│   ├── scorecard.ts       # canonical JSON, commitment, Ed25519 binding
│   ├── anchor.ts          # zkVerify anchor worker (system.remark, async)
│   ├── store.ts           # atomic JSON-file run store
│   ├── keys.ts            # signing key lifecycle (0600 on disk)
│   └── log.ts             # redacting structured logger
├── test/
│   ├── fixtures.ts        # miniature honest / greedy / open target agents
│   └── harness.ts         # 37 checks incl. the greedy agent scoring -30 with 11 traps approved
└── deploy/                # systemd unit + VPS runbook (port 8083)
```

## Setup

```bash
npm install
npm run build
npm test        # 37 local checks — no network, no secrets needed
cp .env.example .env   # configure ANCHOR_MODE + ZKV_ANCHOR_SEED to enable anchoring
npm start
```

With `ANCHOR_MODE=none` (default) everything works locally: runs execute,
scorecards are signed and verifiable; anchoring is just disabled.

To anchor scorecards on-chain: fund a dedicated account with testnet VFY
(faucet), then set `ANCHOR_MODE=volta` + `ZKV_ANCHOR_SEED=<12 words>`.

## Submission context (Agent Games — Wildcard)

- **Agent link:** this repository.
- **Public endpoint:** `https://<spar-host>/` (demo UI + API).
- **Use case:** adversarial self-testing for decision agents — see above.
- **Build context:** this README (taxonomy, scoring, trust model).
- **zkVerify angle:** signed scorecards anchored via `system.remark`; the
  commitment on-chain matches the scorecard's `commitment` field byte-for-byte.
