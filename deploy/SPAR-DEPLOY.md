# Spar — Runbook deploy di VPS (port 8083)

Sejajar dengan gatekeeper (8080) dan web-witness (8082). Caddy tetap satu-satunya
pemilik 80/443.

## 1. Clone + build + test

```bash
cd /root
git clone https://github.com/LutfiAlfiansyah12/spar-agent.git spar
cd spar
npm ci        # full install — build & test butuh devDeps (typescript)
npm run build
npm test      # harus 37 passed, 0 failed
# opsional: npm prune --omit=dev
```

## 2. Config

```bash
cp .env.example .env
nano .env
```

Minimum (anchor ON, testnet — bisa pakai akun anchor yang sama dengan web-witness):

```env
HOST=127.0.0.1
PORT=8083
ANCHOR_MODE=volta
ZKV_ANCHOR_SEED=<12 kata akun anchor — JANGAN pakai akun utama>
```

Atau mulai tanpa anchor: `ANCHOR_MODE=none` (scorecard tetap signed).

## 3. Service

```bash
cp deploy/spar.service /etc/systemd/system/spar.service
systemctl daemon-reload
systemctl enable --now spar
curl -s http://127.0.0.1:8083/healthz
```

## 4. Caddy — tambah satu blok

Buat subdomain DuckDNS baru dulu (misal `0xmurasaki-spar.duckdns.org`), lalu di
`/etc/caddy/Caddyfile` tambah di bawah (JANGAN ubah blok lain):

```caddyfile
0xmurasaki-spar.duckdns.org {
	reverse_proxy 127.0.0.1:8083
}
```

```bash
systemctl reload caddy
curl -s https://0xmurasaki-spar.duckdns.org/healthz
```

## 5. Smoke test end-to-end

Spar target-nya agent lo SENDIRI — paling pas: spar-kan gatekeeper lo!

```bash
# 1. Ambil HMAC secret gatekeeper dari .env gatekeeper di VPS (CATATAN: ini
#    secret produksi — untuk smoke test cukup lihat dia bekerja, atau set
#    auth:"none" ke agent yang memang tanpa auth).
curl -sS -X POST https://0xmurasaki-spar.duckdns.org/spar \
  -H 'content-type: application/json' \
  -d '{"target_url":"https://0xmurasaki-gk.duckdns.org/agent","auth":"hmac","hmac_secret":"<secret gatekeeper>"}'

# 2. Pantau sampai done
curl -s https://0xmurasaki-spar.duckdns.org/runs/<id> | grep -E '"status"|grade|trap_approved'

# 3. Lihat report + anchor
curl -s https://0xmurasaki-spar.duckdns.org/runs/<id>/report
```

Gatekeeper yang sehat harus dapat **grade A, trap_approved 0**.

## 6. Troubleshooting

| Gejala | Cek |
|---|---|
| `BLOCKED_TARGET` | target resolve ke IP private — memang by design; hanya host publik |
| run stuck `running` | target lambat — naikkan `VECTOR_TIMEOUT_MS`; cek `journalctl -u spar` |
| anchor failed | `ZKV_ANCHOR_SEED` kosong / saldo tVFY habis → faucet lagi |
| 429 | `RATE_LIMIT_MAX` di .env, restart service |

## 7. Keamanan

- HMAC secret yang dikirim via POST /spar dipakai **in-memory untuk 1 run saja**,
  tidak pernah disimpan/dilog. Tetap: pakai secret test, bukan secret produksi,
  kalau ragu.
- `ALLOW_PRIVATE_TARGETS=false` WAJIB di produksi (default).
- Jangan commit `.env` / `data/`.
